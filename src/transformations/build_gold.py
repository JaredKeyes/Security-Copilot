from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, max as spark_max, sum as spark_sum, when

SILVER_DIR = Path("data/silver")
GOLD_DIR = Path("data/gold")

def get_spark():
    return (
        SparkSession.builder
        .appName("security-copilot-gold")
        .master("local[*]")
        .getOrCreate()
    )

def main():
    spark = get_spark()

    GOLD_DIR.mkdir(parents=True, exist_ok=True)

    cloudtrail = spark.read.parquet(str(SILVER_DIR / "cloudtrail_enriched"))
    guardduty = spark.read.parquet(str(SILVER_DIR / "guardduty_clean"))
    iam_users = spark.read.parquet(str(SILVER_DIR / "iam_users_clean"))

    security_findings_enriched = (
        guardduty
        .join(
            cloudtrail,
            guardduty.related_event_id == cloudtrail.event_id,
            "left"
        )
        .select(
            guardduty.finding_id,
            guardduty.finding_type,
            guardduty.severity,
            guardduty.severity_label,
            guardduty.title,
            guardduty.description,
            guardduty.user_name,
            guardduty.source_ip_address,
            guardduty.resource_name,
            guardduty.finding_timestamp,
            cloudtrail.event_name,
            cloudtrail.event_outcome,
            cloudtrail.mitre_technique,
            cloudtrail.risk_level,
            cloudtrail.is_known_bad_ip,
            cloudtrail.threat_type,
            cloudtrail.confidence,
        )
    )

    user_risk_summary = (
        cloudtrail
        .groupBy("user_name")
        .agg(
            count("*").alias("total_events"),
            spark_sum(when(col("risk_level") == "high", 1).otherwise(0)).alias("high_risk_events"),
            spark_sum(when(col("is_known_bad_ip") == True, 1).otherwise(0)).alias("known_bad_ip_events"),
            spark_max("event_timestamp").alias("last_seen")
        )
        .join(iam_users, "user_name", "left")
        .withColumn(
            "risk_score",
            col("high_risk_events") * 3
            + col("known_bad_ip_events") * 5
            + when(col("mfa_enabled") == False, 3).otherwise(0)
            + when(col("privilege_level") == "high", 2).otherwise(0)
        )
    )

    ip_reputation_summary = (
        cloudtrail
        .groupBy("source_ip_address")
        .agg(
            count("*").alias("total_events"),
            spark_sum(when(col("is_known_bad_ip") == True, 1).otherwise(0)).alias("known_bad_hits"),
            spark_sum(when(col("risk_level") == "high", 1).otherwise(0)).alias("high_risk_events"),
            spark_max("event_timestamp").alias("last_seen")
        )
    )

    alert_timeline = (
        cloudtrail
        .select(
            "event_id",
            "event_timestamp",
            "user_name",
            "source_ip_address",
            "event_name",
            "resource_name",
            "risk_level",
            "event_outcome",
            "mitre_technique",
            "is_known_bad_ip",
            "threat_type",
        )
        .orderBy("event_timestamp")
    )

    security_findings_enriched.write.mode("overwrite").parquet(str(GOLD_DIR / "security_findings_enriched"))
    user_risk_summary.write.mode("overwrite").parquet(str(GOLD_DIR / "user_risk_summary"))
    ip_reputation_summary.write.mode("overwrite").parquet(str(GOLD_DIR / "ip_reputation_summary"))
    alert_timeline.write.mode("overwrite").parquet(str(GOLD_DIR / "alert_timeline"))

    print("Gold layer created successfully.")

    spark.stop()

if __name__ == "__main__":
    main()