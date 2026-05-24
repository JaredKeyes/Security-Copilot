from pathlib import Path

from pyspark.sql import SparkSession

RAW_DIR = Path("data/raw")
BRONZE_DIR = Path("data/bronze")

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-bronze")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    BRONZE_DIR.mkdir(parents=True, exist_ok=True)

    cloudtrail = spark.read.option("multiLine", "true").json(str(RAW_DIR / "cloudtrail_events.json"))
    guardduty = spark.read.option("multiLine", "true").json(str(RAW_DIR / "guardduty_findings.json"))
    iam_users = spark.read.option("header", True).option("inferSchema", True).csv(str(RAW_DIR / "iam_users.csv"))
    threat_intel = spark.read.option("header", True).option("inferSchema", True).csv(str(RAW_DIR / "threat_intel.csv"))

    cloudtrail.write.mode("overwrite").parquet(str(BRONZE_DIR / "cloudtrail_events"))
    guardduty.write.mode("overwrite").parquet(str(BRONZE_DIR / "guardduty_findings"))
    iam_users.write.mode("overwrite").parquet(str(BRONZE_DIR / "iam_users"))
    threat_intel.write.mode("overwrite").parquet(str(BRONZE_DIR / "threat_intel"))

    print("Bronze layer created successfully.")

    spark.stop()

if __name__ == "__main__":
    main()