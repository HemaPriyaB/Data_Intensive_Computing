# README — CVE 2024 Data Lakehouse Project

## Overview of the Project
This project builds a complete Medallion Architecture (Bronze → Silver → SQL Analysis) for the **2024 Common Vulnerabilities and Exposures (CVE)** dataset using Databricks.

The workflow demonstrates how raw CVE JSON files are ingested, cleaned, normalized, and analyzed to generate actionable cybersecurity insights.

---

# Architecture Summary

## 1. Bronze Layer
**Notebook:** `01_bronze_layer_2024_starter.ipynb`  
**Objective:** Ingest all raw CVE JSON files for 2024 and register them as a Delta table.

### Key Steps
- Reading raw JSON files with recursive lookup
- Parsing `cveMetadata` (ID, published/updated timestamps)
- Adding lineage column (source file)
- Filtering to include only 2024 records
- Writing results to Delta:

  - **Path:** `/Volumes/workspace/default/assignment1/bronze`  
  - **Table:** `workspace.default.cve_bronze_records`

### Bronze Data Quality Checks
- Record count validation  
- Null `cve_id` check  
- Uniqueness check  

---

## 2. Silver Layer
**Notebook:** `02_bronze_to_silver.ipynb`  
**Objective:** Clean and normalize nested CVE JSON into relational tables.

### Silver Tables Created

### 1. `cve_core`
- One row per CVE  
- Columns include:
  - `cve_id`
  - `published_date`
  - `last_modified_date`
  - `cvss_score`
  - `cvss_vector`
  - `description`

### 2. `cve_affected_products`
- Exploded list of affected vendors/products  
- One row per vendor–product–version combination  

### Key Insights
- Parsing nested JSON from `containers.cna`
- Resolving CVSS score versions (v3.1 → v3.0 → v2 fallback)
- Extracting English descriptions
- Exploding `affected[].versions[]`
- Writing to Delta locations:
  - `/silver/core`
  - `/silver/affected_products`
- Registering tables:
  - `workspace.default.cve_core`
  - `workspace.default.cve_affected_products`

### Silver Data Quality Checks
- Null CVE ID validation  
- Row count comparisons  
- Join integrity between core and affected tables  

---

## 3. SQL Analysis Layer (Exploration & Insights)
**File:** `03_exploratory_analysis.sql`  
**Objective:** Perform cybersecurity insights and analytics using Delta tables.

### Analysis Components

#### A. Row Count Verification
- Validating that Bronze and Silver tables contain expected records.

#### B. Temporal Analysis
- Monthly CVE counts for 2024  
- Weekly distributions  
- Time lag between published and last-modified dates  

#### C. Severity or Risk Analysis
- CVSS severity buckets: Critical, High, Medium, Low  
- Percentage contribution of severity categories  
- Count of unscored CVEs  

#### D. Vendor Intelligence
- Top 25 vendors by vulnerability count  
- Vendor-level severity profiles  
- High-risk vendor summaries (avg CVSS, High+Critical counts)  

#### E. High-Risk CVE Identification
- Top 50 highest-risk CVEs  
- High-risk products per key vendor  

#### F. Reusable Views (Mini Gold Layer)
- `cve_severity_view`  
- `vendor_risk_summary`  
- % contribution of top 10 vendors  

---

# Repository Structure

---

# How to Run This Project

## Prerequisites
- Databricks Workspace  
- Unity Catalog enabled  
- Read access to DBFS/Volumes  

## Steps to Execute
1. Import all notebooks and SQL files into Databricks.
2. Run the **Bronze notebook** to ingest raw CVE JSON into Delta.
3. Run the **Silver notebook** to build normalized relational tables.
4. Run the **SQL Analysis** to generate insights, dashboards, and validations.

---

# What This Project Demonstrates
- Medallion Architecture implementation on Databricks  
- JSON ingestion and schema normalization techniques  
- Flattening and exploding nested arrays  
- CVSS scoring extraction and unification  
- End-to-end cybersecurity analytics workflow  
- SQL-based risk intelligence reporting  

---

# Key Learning Outcomes
By completing this project, you demonstrate skills in:
- Databricks Delta Lake architecture  
- SQL analytics on cybersecurity datasets  
- Data engineering pipeline development  
- Normalizing deeply nested JSON structures  
- Vendor and product-level vulnerability analysis  
- Building reproducible and production-ready workflows  

---
