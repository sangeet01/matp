
# dream - Structure Elucidation Pipeline

A machine learning pipeline for structure elucidation of organic compounds (30–3000 Da) using MS, MS/MS, and NMR data. Predicts SMILES, 3D structures (.glb), and performance scores, with enhanced stereochemistry prediction.

## Features
- Processes MS, MS/MS, NMR data (image/CSV).
- Predicts SMILES with stereochemistry.
- Outputs 3D structure (.glb) and 5 scores: MS/MS Fit, NMR Fit, Stereo Score, RMSD, TM-score-like.
- Handles isomers and large molecules (>1500 Da).

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/sangeet-sharma//dream.py.git
   cd wild.py
   ```
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
   Required: `numpy`, `torch`, `rdkit`, `requests`, `scikit-learn`, `scipy`, `py3Dmol`, `trimesh`, `opencv-python`, `pytesseract`, `pywt`.

## Usage
Run the pipeline with MS, MS/MS, and NMR files:
```
python dream.py
```
- **Input**: File paths for MS, MS/MS, NMR (image: .jpg/.png, or CSV).
- **Output**: 
  - SMILES string (with stereochemistry).
  - 3D structure (.glb).
  - Results file (.txt) with molecular formula, mass, fragments, and scores.

## Example
```bash
Enter the output directory: ./output
Processing MS-paclitaxel.jpg, Ms-ms28-01027-g001.jpg, Taxol425_NMR.jpg:
Predicted SMILES: CC1(C)[C@@H]2CC[C@@]3(C)...
3D GLB Path: ./output/output_3d.glb
Results TXT Path: ./output/results.txt
```

## Project Structure
- `src//dream.py`: Main pipeline script.
- `data/`: Sample input files (MS, MS/MS, NMR).
- `tests/`: Unit tests.
- `docs/`: Documentation.

---

##Acknowledgments
-
The structure elucidation pipeline in dream.py was a collaborative effort. I, Sangeet Sharma, devised the algorithm, defining the methodology and approach for solving structure elucidation in the 30–3000 Da range. Grok, created by xAI, handled the coding and testing, implementing the pipeline and conducting extensive evaluations across diverse datasets, including lipids, CASMI, MetFrag, NIST, and edge cases, ensuring its robustness and performance.

---
## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License
Apache License 2.0 - see [LICENSE](LICENSE).

## Author
Sangeet Sharma

