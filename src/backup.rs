use std::fs::{self, File};
use std::io::{self, BufWriter, Cursor, Read, Write};
use std::path::Path;

use bincode;
use chrono::{NaiveDateTime, Utc};
use log::{info, warn};
use rusoto_core::Region;
use rusoto_s3::{
    CreateBucketRequest, DeleteObjectRequest, GetObjectRequest, ListObjectsV2Request,
    PutObjectRequest, S3Client, S3,
};
use serde::Deserialize;
use sled::Db;
use tempfile::tempdir;
use tokio::io::AsyncReadExt as _;
use walkdir::WalkDir;
use zip::write::{FileOptions, ZipWriter};
use zip::ZipArchive;

#[derive(Deserialize)]
struct S3Config {
    s3_endpoint: String,
    s3_bucket: String,
    s3_access_key: String,
    s3_secret_key: String,
    s3_region: String,
}

async fn get_s3_client() -> Result<(S3Client, S3Config), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string("config.json")?;
    let config: S3Config = serde_json::from_str(&config_str)?;

    let region = Region::Custom {
        name: config.s3_region.clone(),
        endpoint: config.s3_endpoint.clone(),
    };
    let client = S3Client::new_with(
        rusoto_core::request::HttpClient::new()?,
        rusoto_core::credential::StaticProvider::new_minimal(
            config.s3_access_key.clone(),
            config.s3_secret_key.clone(),
        ),
        region,
    );

    let list_buckets = client.list_buckets().await?;
    let bucket_exists = list_buckets
        .buckets
        .unwrap_or_default()
        .iter()
        .any(|bucket| bucket.name.as_deref() == Some(&config.s3_bucket));

    if !bucket_exists {
        info!("Creating S3 bucket: {}", config.s3_bucket);
        let create_bucket_req = CreateBucketRequest {
            bucket: config.s3_bucket.clone(),
            ..Default::default()
        };
        client.create_bucket(create_bucket_req).await?;
        info!("Successfully created S3 bucket: {}", config.s3_bucket);
    }

    Ok((client, config))
}

/// Creates a backup by creating a logical snapshot of the database and zipping it with logs.
pub async fn backup_to_s3(db: &Db) -> Result<(), Box<dyn std::error::Error>> {
    let (client, config) = get_s3_client().await?;
    let backup_timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_file_name = format!("backup_{}.zip", backup_timestamp);
    info!("Creating backup: {}", backup_file_name);

    let temp_dir = tempdir()?;
    let export_file_path = temp_dir.path().join("db_export.dat");

    // 1. Create a logical backup by iterating and serializing key-value pairs.
    {
        let file = File::create(&export_file_path)?;
        let mut writer = BufWriter::new(file);
        info!("Exporting database records to temporary file...");
        for item in db.iter() {
            let (key, value) = item?;
            // Serialize as a tuple of slices
            bincode::serialize_into(&mut writer, &(&key[..], &value[..]))?;
        }
        writer.flush()?; // Ensure all buffered data is written to the file
    }
    info!("Database export complete.");

    // 2. Create a zip archive in memory
    let zip_buffer = {
        let mut buff = Vec::new();
        {
            let cursor = Cursor::new(&mut buff);
            let mut zip = ZipWriter::new(cursor);
            let options =
                FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("db_export.dat", options)?;
            let mut f = File::open(&export_file_path)?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;

            add_dir_to_zip(&mut zip, "data/logs", "logs", options)?;
            zip.finish()?;
        }
        buff
    };

    // 3. Upload to S3
    let put_request = PutObjectRequest {
        bucket: config.s3_bucket.clone(),
        key: backup_file_name.clone(),
        body: Some(zip_buffer.into()),
        ..Default::default()
    };
    client.put_object(put_request).await?;
    info!("Successfully uploaded backup: {}", backup_file_name);

    delete_previous_backups(&client, &config.s3_bucket, &backup_file_name).await?;
    Ok(())
}

async fn delete_previous_backups(
    client: &S3Client,
    bucket: &str,
    current_backup: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let list_req = ListObjectsV2Request {
        bucket: bucket.to_string(),
        ..Default::default()
    };
    let result = client.list_objects_v2(list_req).await?;
    if let Some(contents) = result.contents {
        for object in contents {
            if let Some(key) = object.key {
                if key != current_backup {
                    info!("Deleting old backup: {}", key);
                    let delete_req = DeleteObjectRequest {
                        bucket: bucket.to_string(),
                        key: key.clone(),
                        ..Default::default()
                    };
                    client.delete_object(delete_req).await?;
                }
            }
        }
    }
    Ok(())
}

/// Restores the database from the latest logical backup in S3.
pub async fn restore_from_s3() -> Result<(), Box<dyn std::error::Error>> {
    info!("Attempting to restore from the latest S3 backup.");
    let (client, config) = get_s3_client().await?;

    let list_req = ListObjectsV2Request {
        bucket: config.s3_bucket.clone(),
        ..Default::default()
    };
    let result = client.list_objects_v2(list_req).await?;

    let latest_backup_key = result
        .contents
        .unwrap_or_default()
        .into_iter()
        .filter_map(|obj| obj.key)
        .filter(|key| key.starts_with("backup_") && key.ends_with(".zip"))
        .max_by_key(|key| {
            let timestamp_str = key
                .strip_prefix("backup_")
                .and_then(|s| s.strip_suffix(".zip"))
                .unwrap_or("");
            // Handle parsing errors by defaulting to the minimum time, ensuring Ord is implemented.
            NaiveDateTime::parse_from_str(timestamp_str, "%Y%m%d_%H%M%S")
                .unwrap_or(NaiveDateTime::MIN)
        });

    if let Some(backup_key) = latest_backup_key {
        info!("Found latest backup: {}", backup_key);
        let get_req = GetObjectRequest {
            bucket: config.s3_bucket,
            key: backup_key.clone(),
            ..Default::default()
        };
        let result = client.get_object(get_req).await?;
        let mut body = result
            .body
            .ok_or("Backup file from S3 is empty")?
            .into_async_read();
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).await?;

        let temp_dir = tempdir()?;
        let reader = Cursor::new(bytes);
        let mut archive = ZipArchive::new(reader)?;
        archive.extract(temp_dir.path())?;
        info!("Extracted backup to temporary directory.");

        let db_path = Path::new("data/db");
        let logs_path = Path::new("data/logs");
        let export_file_in_temp = temp_dir.path().join("db_export.dat");
        let logs_in_temp = temp_dir.path().join("logs");

        if !export_file_in_temp.exists() {
            return Err("Backup is invalid: 'db_export.dat' not found.".into());
        }

        // 1. Restore database from logical backup
        info!("Clearing old database and restoring from backup...");
        if db_path.exists() {
            fs::remove_dir_all(db_path)?;
        }
        let temp_db = sled::open(db_path)?; // Open a new, empty DB at the correct path

        let file = File::open(&export_file_in_temp)?;
        let mut reader = io::BufReader::new(file);

        // Loop until EOF is reached, which will result in a deserialization error
        while let Ok((key, value)) =
            bincode::deserialize_from::<_, (Vec<u8>, Vec<u8>)>(&mut reader)
        {
            temp_db.insert(key, value)?;
        }

        temp_db.flush_async().await?; // Ensure all data is written to disk
        info!("Database successfully restored.");
        // The db handle will be closed when `temp_db` goes out of scope.

        // 2. Restore logs
        if logs_path.exists() {
            fs::remove_dir_all(logs_path)?;
        }
        fs::create_dir_all(logs_path)?;
        if logs_in_temp.exists() {
            info!("Restoring logs...");
            copy_dir_all(logs_in_temp, logs_path)?;
            info!("Logs successfully restored.");
        }

        info!("Successfully restored from backup: {}", backup_key);
        Ok(())
    } else {
        warn!("No valid backups found in S3 bucket. Nothing to restore.");
        Err("No valid backups found in S3 bucket.".into())
    }
}

fn add_dir_to_zip<W: Write + io::Seek>(
    zip: &mut ZipWriter<W>,
    dir_to_add: &str,
    base_in_zip: &str,
    options: FileOptions,
) -> io::Result<()> {
    if !Path::new(dir_to_add).exists() {
        return Ok(());
    }
    let walker = WalkDir::new(dir_to_add).into_iter();
    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(dir_to_add)).unwrap();
        let zip_path_str = Path::new(base_in_zip)
            .join(name)
            .to_string_lossy()
            .into_owned();

        if path.is_file() {
            zip.start_file(zip_path_str, options)?;
            let mut f = File::open(path)?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
        } else if !name.as_os_str().is_empty() {
            zip.add_directory(zip_path_str, options)?;
        }
    }
    Ok(())
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.as_ref().join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}