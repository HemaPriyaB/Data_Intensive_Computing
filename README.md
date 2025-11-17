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
**Objective:** Perform cybersecurity insights and analyt
