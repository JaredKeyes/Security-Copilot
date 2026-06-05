from itertools import chain
from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, create_map, lit, to_timestamp, when


BRONZE_DIR = Path("data/bronze")
SILVER_DIR = Path("data/silver")

MITRE_MAP = {
    "ConsoleLogin": "T1078 - Valid Accounts",
    "AssumeRole": "T1078 - Valid Accounts",
    "ListBuckets": "T1619 - Cloud Storage Object Discovery",
    "GetObject": "T1530 - Data from Cloud Storage",
    "PutObject": "T1105 - Ingress Tool Transfer",
    "CreateAccessKey": "T1098 - Account Manipulation",
    "DeleteTrail": "T1562.008 - Disable Cloud Logs",
    "AuthorizeSecurityGroupIngress": "T1578 - Modify Cloud Compute Infrastructure",
    "RunInstances": "T1578 - Modify Cloud Compute Infrastructure",
    "StopLogging": "T1562.008 - Disable Cloud Logs",
}

SENSITIVE_EVENTS = {
    "CreateAccessKey",
    "DeleteTrail",
    "AuthorizeSecurityGroupIngress",
    "StopLogging",
    "AssumeRole",
}

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-silver")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    SILVER_DIR.mkdir(parents=True, exist_ok=True)

    cloudtrail = spark.read.parquet(str(BRONZE_DIR / "cloudtrail_events"))
    guardduty = spark.read.parquet(str(BRONZE_DIR / "guardduty_findings"))
    iam_users = spark.read.parquet(str(BRONZE_DIR / "iam_users"))
    threat_intel = spark.read.parquet(str(BRONZE_DIR / "threat_intel"))

    mitre_expr = create_map([lit(x) for x in chain(*MITRE_MAP.items())])

    cloudtrail_clean = (
        cloudtrail
        .withColumn("event_timestamp", to_timestamp(col("event_time")))
        .withColumn(
            "mitre_technique", 
            when(mitre_expr.getItem(col("event_name")).isNotNull(), mitre_expr.getItem(col("event_name")))
            .otherwise("Unknown")
        )
        .withColumn("is_sensitive_event", col("event_name").isin(SENSITIVE_EVENTS))
        .withColumn(
            "risk_level",
            when(col("event_name").isin("DeleteTrail", "StopLogging", "CreateAccessKey"), "high")
            .when(col("event_name").isin("AssumeRole", "AuthorizeSecurityGroupIngress"), "medium")
            .otherwise("low")
        )
        .withColumn(
            "event_outcome",
            when(col("error_code").isNotNull(), "failed").otherwise("success")
        )
    )

    guardduty_clean = (
        guardduty
        .withColumn("finding_timestamp", to_timestamp(col("created_at")))
        .withColumn(
            "severity_label",
            when(col("severity") >= 7.0, "high")
            .when(col("severity") >= 4.0, "medium")
            .otherwise("low")
        )
    )

    cloudtrail_enriched = (
        cloudtrail_clean
        .join(
            threat_intel,
            cloudtrail_clean.source_ip_address == threat_intel.ip_address,
            "left"
        )
        .drop("ip_address")
        .withColumn(
            "is_known_bad_ip",
            when(col("threat_type").isNotNull(), True).otherwise(False)
        )
    )

    cloudtrail_enriched.write.mode("overwrite").parquet(str(SILVER_DIR / "cloudtrail_enriched"))
    guardduty_clean.write.mode("overwrite").parquet(str(SILVER_DIR / "guardduty_clean"))
    iam_users.write.mode("overwrite").parquet(str(SILVER_DIR / "iam_users_clean"))
    threat_intel.write.mode("overwrite").parquet(str(SILVER_DIR / "threat_intel_clean"))

    print("Silver layer created successfully.")

    spark.stop()

if __name__ == "__main__":
    main()