[![DOI](https://zenodo.org/badge/github/1146947486.svg)](https://doi.org/10.5281/zenodo.24563750)

# Forensic Studio 2.0

Forensic Studio 2.0 is a modern, bilingual (English / العربية) desktop graphical user interface (GUI) built on top of the Volatility 3 memory forensics framework. It guides investigators through a structured, non-destructive workflow—from raw memory image hashing to automated MITRE ATT&CK threat mapping and ready-to-deliver forensic reports.

---

## Key Features
<img width="1456" height="819" alt="photo_2026-11-26_13-33-32" src="https://github.com/user-attachments/assets/383a5ef8-3e83-4b49-939a-29067e516a38" />

<img width="1456" height="819" alt="photo_2026-11-22_22-13-00" src="https://github.com/user-attachments/assets/bf7f7446-3c4f-4c7e-8c49-dad40dd37244" />

<img width="1456" height="819" alt="photo_2026-11-22_22-12-59" src="https://github.com/user-attachments/assets/e080f986-05bd-4fb4-b7d0-f7aee3e2ecd9" />

* Evidence Integrity & Case Management: Computes MD5, SHA-1, and SHA-256 hashes automatically upon ingestion and ensures read-only handling of memory dumps.
* Automated Analysis & Job Queue: Eliminates command-line complexity with pre-built triage scenarios, a searchable plugin catalog, and a sequential execution queue.
* Interactive Results & Process Tree: Provides sortable tables, smart filtering, and hierarchical process-tree visualization to spot anomalous parent-child processes.
* MITRE ATT&CK Integration: Maps suspicious artifacts directly to corresponding MITRE ATT&CK techniques with verification guidance.
* Tamper-Evident Audit Log & Bilingual Reports: Tracks every investigative action and exports structured HTML reports in both English and Arabic.

---

## Installation & Quick Start

1. Clone the repository:
  
   git clone https://github.com/TheEvidenceHunter/AmeerRasim-Forensic-GUI.git
   cd AmeerRasim-Forensic-GUI
   
2. Install dependencies:
  
   pip install -e ".[gui]"
   
3. Launch Forensic Studio 2.0:
  
   python forensic_studio.py
   
---

## Documentation & Citation

* For detailed architecture and usage instructions, see README_FORENSIC_STUDIO.md.
* Built upon the [Volatility 3 Framework](https://github.com).
