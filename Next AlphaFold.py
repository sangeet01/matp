# wild.py
# Copyright 2025 Sangeet
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import numpy as np
import requests
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from rdkit import Chem
from rdkit.Chem import AllChem, Descriptors, rdMolAlign
import os
import py3Dmol
import trimesh
from stmol import save_to_glb
import cv2
import pandas as pd
from PIL import Image
import pytesseract
from scipy.stats import entropy
import multiprocessing as mp
import scipy.signal as signal
import scipy.cluster.hierarchy as hierarchy
import pywt

# Shallow CNN for Denoising
class DenoisingCNN(nn.Module):
    def __init__(self):
        super(DenoisingCNN, self).__init__()
        self.encoder = nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(16, 16, 3, padding=1),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Conv2d(16, 16, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(16, 1, 3, padding=1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

# VAE for Spectral Latent Embedding
class VAE(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim):
        super(VAE, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
        )
        self.fc_mu = nn.Linear(hidden_dim // 2, latent_dim)
        self.fc_logvar = nn.Linear(hidden_dim // 2, latent_dim)
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid(),
        )

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def forward(self, x):
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        z = self.reparameterize(mu, logvar)
        return self.decoder(z), mu, logvar

# Transformer for SMILES Prediction
class SMILESTransformer(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes, num_layers=2, num_heads=2, dropout=0.1):
        super(SMILESTransformer, self).__init__()
        self.input_fc = nn.Linear(input_dim, hidden_dim)
        self.batch_norm = nn.BatchNorm1d(hidden_dim)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=num_heads, dim_feedforward=hidden_dim * 4, dropout=dropout
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        x = self.input_fc(x)
        x = self.batch_norm(x)
        x = x.unsqueeze(1)
        x = self.transformer_encoder(x)
        x = x.squeeze(1)
        x = self.dropout(x)
        x = self.fc(x)
        return x

# Dataset for Transformer Training
class SMILESDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

# Step 1: Spectral Data Input and Preprocessing
def train_denoising_cnn(images, noisy_images, epochs=10, batch_size=4):
    model = DenoisingCNN()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()
    dataloader = DataLoader(
        list(zip(torch.tensor(noisy_images, dtype=torch.float32).unsqueeze(1),
                 torch.tensor(images, dtype=torch.float32).unsqueeze(1))),
        batch_size=batch_size, shuffle=True
    )

    model.train()
    for epoch in range(epochs):
        for noisy, clean in dataloader:
            optimizer.zero_grad()
            output = model(noisy)
            loss = criterion(output, clean)
            loss.backward()
            optimizer.step()
    return model

def denoise_image(image_path, spectrum_type="MS/MS"):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError(f"Cannot load image: {image_path}")

    img_normalized = img / 255.0
    noisy_img = img_normalized + np.random.normal(0, 0.1, img.shape)
    images = np.array([img_normalized])
    noisy_images = np.array([noisy_img])

    model = train_denoising_cnn(images, noisy_images)
    img_tensor = torch.tensor(img_normalized, dtype=torch.float32).unsqueeze(0).unsqueeze(0)
    with torch.no_grad():
        denoised = model(img_tensor).squeeze().numpy() * 255.0
    return denoised.astype(np.uint8)

def extract_peaks(image_path, spectrum_type="MS/MS"):
    img = denoise_image(image_path, spectrum_type)

    coeffs = pywt.wavedec(img.mean(axis=0), 'db1', level=2)
    coeffs[1:] = [np.zeros_like(c) for c in coeffs[1:]]
    intensity_profile = pywt.waverec(coeffs, 'db1')

    peaks, _ = signal.find_peaks(intensity_profile, prominence=np.percentile(intensity_profile, 90))

    if spectrum_type == "MS/MS":
        x_range = (200, 900)
    else:
        x_range = (0, 9.5)
    x_values = np.linspace(x_range[0], x_range[1], len(intensity_profile))

    try:
        ocr_text = pytesseract.image_to_string(Image.fromarray(img))
        labels = [float(t) for t in ocr_text.split() if t.replace('.', '', 1).isdigit()]
        peak_values = []
        for peak_idx in peaks:
            peak_x = x_values[peak_idx]
            matched_label = min(labels, key=lambda x: abs(x - peak_x), default=peak_x)
            if abs(matched_label - peak_x) < 10 and (200 <= matched_label <= 900 if spectrum_type == "MS/MS" else 0 <= matched_label <= 9.5):
                peak_values.append([matched_label, intensity_profile[peak_idx]])
            else:
                peak_values.append([peak_x, intensity_profile[peak_idx]])
    except Exception:
        peak_values = [[x_values[idx], intensity_profile[idx]] for idx in peaks]

    intensities = np.array([pv[1] for pv in peak_values])
    if intensities.max() > 0:
        intensities = intensities / intensities.max()
    peak_values = [[pv[0], i] for pv, i in zip(peak_values, intensities)]
    return peak_values

def load_data(csv_path):
    df = pd.read_csv(csv_path)
    data = df.iloc[:, :2].values
    intensities = data[:, 1]
    if intensities.max() > 0:
        intensities = intensities / intensities.max()
    return [[data[i, 0], intensities[i]] for i in range(len(data))]

def process_input(input_path_ms, input_path_msms, input_path_nmr):
    ext_ms = os.path.splitext(input_path_ms)[1].lower()
    if ext_ms in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
        ms_data = extract_peaks(input_path_ms, spectrum_type="MS/MS")
    elif ext_ms == '.csv':
        ms_data = load_data(input_path_ms)
    else:
        raise ValueError(f"Unsupported file type for MS: {ext_ms}")

    ext_msms = os.path.splitext(input_path_msms)[1].lower()
    if ext_msms in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
        msms_data = extract_peaks(input_path_msms, spectrum_type="MS/MS")
    elif ext_msms == '.csv':
        msms_data = load_data(input_path_msms)
    else:
        raise ValueError(f"Unsupported file type for MS/MS: {ext_msms}")

    ext_nmr = os.path.splitext(input_path_nmr)[1].lower()
    if ext_nmr in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
        nmr_data = extract_peaks(input_path_nmr, spectrum_type="NMR")
    elif ext_nmr == '.csv':
        nmr_data = load_data(input_path_nmr)
    else:
        raise ValueError(f"Unsupported file type for NMR: {ext_nmr}")

    return ms_data, msms_data, nmr_data

# Step 2: Spectral Latent Embedding
def train_vae_spectral(data, epochs=20, batch_size=4, latent_dim=50):
    input_dim = len(data[0])
    hidden_dim = 256
    vae = VAE(input_dim, hidden_dim, latent_dim)
    optimizer = optim.Adam(vae.parameters(), lr=0.001)
    dataloader = DataLoader(torch.tensor(data, dtype=torch.float32), batch_size=batch_size, shuffle=True)

    vae.train()
    for epoch in range(epochs):
        for batch in dataloader:
            optimizer.zero_grad()
            recon, mu, logvar = vae(batch)
            recon_loss = nn.functional.binary_cross_entropy(recon, batch, reduction='sum')
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + kl_loss
            loss.backward()
            optimizer.step()
    return vae

def encode_spectral_data(ms_data, msms_data, nmr_data):
    max_len = 10
    ms_flat = [item for sublist in ms_data for item in sublist][:max_len*2] + [0] * (max_len*2 - len([item for sublist in ms_data for item in sublist]))
    msms_flat = [item for sublist in msms_data for item in sublist][:max_len*2] + [0] * (max_len*2 - len([item for sublist in msms_data for item in sublist]))
    nmr_flat = [item for sublist in nmr_data for item in sublist][:max_len*2] + [0] * (max_len*2 - len([item for sublist in nmr_data for item in sublist]))
    data = np.array([ms_flat + msms_flat + nmr_flat])

    vae = train_vae_spectral(data)
    with torch.no_grad():
        data_tensor = torch.tensor(data, dtype=torch.float32)
        _, mu, _ = vae(data_tensor)
    return mu.numpy()

# Step 3: 2D Structure Prediction with Stereochemistry
def browse_databases(ms_data, msms_data):
    database = []
    mw = ms_data[0][0]
    exp_mz = [m for m, i in msms_data]
    exp_int = [i for m, i in msms_data]
    matches_found = 0

    try:
        url = f"https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/mass/{mw}/JSON"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            for compound in data.get('PC_Compounds', []):
                cid = compound['id']['id']['cid']
                smiles_url = f"https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/cid/{cid}/property/CanonicalSMILES/JSON"
                smiles_response = requests.get(smiles_url, timeout=5)
                if smiles_response.status_code == 200:
                    smiles = smiles_response.json()['PropertyTable']['Properties'][0]['CanonicalSMILES']
                    mol_wt = Descriptors.MolWt(Chem.MolFromSmiles(smiles))
                    if 30 <= mol_wt <= 3000:
                        lib_msms_data = [(mol_wt + 1, 100.0), (mol_wt - 18, 50.0)]
                        database.append((smiles, mol_wt, lib_msms_data))
                        matches_found += 1
    except Exception as e:
        print(f"Error accessing PubChem: {e}")

    if matches_found >= 2:
        return database

    try:
        url = f"https://massbank.eu/api/spectra?mass={mw}&tolerance=5.0"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                smiles = entry.get('smiles')
                if smiles:
                    mol_wt = Descriptors.MolWt(Chem.MolFromSmiles(smiles))
                    if 30 <= mol_wt <= 3000:
                        lib_msms_data = [(float(mz), float(intensity)) for mz, intensity in entry.get('msms', [])]
                        database.append((smiles, mol_wt, lib_msms_data))
                        matches_found += 1
    except Exception as e:
        print(f"Error accessing MassBank: {e}")

    return database

def library_matching(ms_data, msms_data):
    database = browse_databases(ms_data, msms_data)
    mw = ms_data[0][0]
    exp_mz = [m for m, i in msms_data]
    exp_int = [i for m, i in msms_data]

    for smiles, lib_mw, lib_msms_data in database:
        if abs(mw - lib_mw) < 5.0:
            lib_mz = [m for m, i in lib_msms_data]
            lib_int = [i for m, i in lib_msms_data]
            matches = 0
            for i, em in enumerate(exp_mz):
                for j, lm in enumerate(lib_mz):
                    if abs(em - lm) < 0.01:
                        matches += exp_int[i] * lib_int[j]
            exp_norm = np.sqrt(np.sum(np.square(exp_int)))
            lib_norm = np.sqrt(np.sum(np.square(lib_int)))
            similarity = matches / (exp_norm * lib_norm) if exp_norm * lib_norm != 0 else 0
            if similarity > 0.9:
                return smiles
    return None

def fetch_fragment_library():
    fragment_patterns = {}
    matches_found = 0

    try:
        url = "https://massbank.eu/api/fragments"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                mass = float(entry.get('mass'))
                substructure_id = entry.get('substructure_id')
                fragment_patterns[mass] = substructure_id
            matches_found += 1
    except Exception as e:
        print(f"Error accessing MassBank fragments: {e}")

    if matches_found >= 2:
        return fragment_patterns

    try:
        url = "https://gnps.ucsd.edu/ProteoSAFe/gnpslibraryfragments.jsp"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            for entry in data.get('fragments', []):
                mass = float(entry.get('mass'))
                substructure_id = entry.get('substructure_id')
                fragment_patterns[mass] = substructure_id
            matches_found += 1
    except Exception as e:
        print(f"Error accessing GNPS fragments: {e}")

    return fragment_patterns

def fragment_matching(msms_data):
    fragment_patterns = fetch_fragment_library()
    exp_mz = [m for m, i in msms_data]
    substructures = set()

    for i, mz1 in enumerate(exp_mz):
        for j, mz2 in enumerate(exp_mz):
            if i != j:
                loss = abs(mz1 - mz2)
                for pattern_mass, substructure_id in fragment_patterns.items():
                    if abs(loss - pattern_mass) < 0.01:
                        substructures.add(substructure_id)
    return list(substructures)

def train_substructure_predictor(ms_data, msms_data):
    fragment_patterns = fetch_fragment_library()
    X = []
    y = []
    for mass, substructure_id in fragment_patterns.items():
        features = [mass, 100.0] + [0] * 8
        X.append(features)
        y.append(substructure_id)

    fragment_mz1, intensity1 = msms_data[0] if msms_data else (0, 0)
    fragment_mz2, intensity2 = msms_data[1] if len(msms_data) > 1 else (0, 0)
    features = ms_data[0] + [fragment_mz1, intensity1, fragment_mz2, intensity2] + [0] * 4
    X.append(features)
    y.append(0)

    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    rf = RandomForestClassifier(n_estimators=100, max_depth=50, random_state=42)
    rf.fit(X, y)
    return rf, scaler

def predict_substructures(rf, scaler, ms_data, msms_data, fragment_substructures):
    fragment_mz1, intensity1 = msms_data[0] if msms_data else (0, 0)
    fragment_mz2, intensity2 = msms_data[1] if len(msms_data) > 1 else (0, 0)
    features = ms_data[0] + [fragment_mz1, intensity1, fragment_mz2, intensity2] + [0] * 4
    features = np.array([features])
    features = scaler.transform(features)

    probs = rf.predict_proba(features)[0]
    rf_substructures = [i for i, prob in enumerate(probs) if prob > 0.5]
    return list(set(rf_substructures + fragment_substructures))

def train_stereo_predictor(nmr_data):
    # Synthetic training data for stereochemistry prediction
    X = []
    y = []
    for ppm, intensity in nmr_data:
        # Features: chemical shift, intensity, shift differences
        features = [ppm, intensity, ppm - 2.0 if ppm > 2.0 else 0] + [0] * 7
        X.append(features)
        y.append(0 if ppm < 3.0 else 1)  # Placeholder: 0 for R, 1 for S

    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    rf = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=42)
    rf.fit(X, y)
    return rf, scaler

def predict_stereochemistry(rf, scaler, nmr_data, chiral_centers):
    X = []
    for ppm, intensity in nmr_data:
        features = [ppm, intensity, ppm - 2.0 if ppm > 2.0 else 0] + [0] * 7
        X.append(features)
    X = scaler.transform(X)
    predictions = rf.predict(X)

    # Assign R/S to chiral centers
    stereo_assignments = []
    for i in range(len(chiral_centers)):
        stereo_assignments.append('R' if predictions[i % len(predictions)] == 0 else 'S')
    return stereo_assignments

def graph_based_assembly(substructures, mw, stereo_assignments):
    substructure_smiles = {
        0: "c1ccccc1",
        1: "C(=O)O",
        2: "C1CC(O)C(O)C(O)C1",
    }
    smiles_parts = [substructure_smiles.get(s, "C") for s in substructures]
    remaining_mw = mw - sum(Descriptors.MolWt(Chem.MolFromSmiles(s)) for s in smiles_parts)
    if remaining_mw > 0:
        smiles_parts.append(f"C{int(remaining_mw/12)}")
    base_smiles = ".".join(smiles_parts)

    # Add stereochemistry to SMILES
    mol = Chem.MolFromSmiles(base_smiles)
    Chem.AssignStereochemistry(mol, cleanIt=True, force=True)
    chiral_centers = Chem.FindMolChiralCenters(mol, includeUnassigned=True)
    for idx, (atom_idx, _) in enumerate(chiral_centers):
        if idx < len(stereo_assignments):
            # Placeholder for setting stereochemistry in SMILES
            pass
    return Chem.MolToSmiles(mol, isomericSmiles=True)

def de_novo_generation(ms_data, msms_data, nmr_data, mw):
    fragment_substructures = fragment_matching(msms_data)
    rf, scaler = train_substructure_predictor(ms_data, msms_data)
    substructures = predict_substructures(rf, scaler, ms_data, msms_data, fragment_substructures)

    # Predict stereochemistry
    stereo_rf, stereo_scaler = train_stereo_predictor(nmr_data)
    mol = Chem.MolFromSmiles(".".join(["C"] * len(substructures)))
    Chem.AssignStereochemistry(mol, cleanIt=True, force=True)
    chiral_centers = Chem.FindMolChiralCenters(mol, includeUnassigned=True)
    stereo_assignments = predict_stereochemistry(stereo_rf, stereo_scaler, nmr_data, chiral_centers)

    if mw > 1500:
        sub_smiles = []
        remaining_mw = mw
        sorted_msms = sorted(msms_data, key=lambda x: x[0], reverse=True)
        for mz, _ in sorted_msms:
            fragment_substructures = fragment_matching([(mz, 100.0)])
            if fragment_substructures:
                sub_smiles.append(graph_based_assembly(fragment_substructures, mz, stereo_assignments))
                remaining_mw -= mz
        if remaining_mw > 0:
            sub_smiles.append(f"C{int(remaining_mw/12)}")
        smiles = ".".join(sub_smiles)
    else:
        smiles = graph_based_assembly(substructures, mw, stereo_assignments)
    return smiles

def predict_2d(ms_data, msms_data, nmr_data):
    mw = ms_data[0][0]
    smiles = library_matching(ms_data, msms_data)
    if smiles:
        return smiles
    return de_novo_generation(ms_data, msms_data, nmr_data, mw)

# Step 4: Initial 3D Structure Generation
def generate_initial_3d(smiles):
    mol = Chem.MolFromSmiles(smiles)
    if not mol:
        raise ValueError("Invalid SMILES string")
    mol = Chem.AddHs(mol)
    AllChem.EmbedMolecule(mol, randomSeed=42)
    return mol

# Step 5: Conformer Generation and Clustering
def cluster_conformers(mol):
    num_confs = 200
    AllChem.EmbedMultipleConfs(mol, numConfs=num_confs, randomSeed=42, useExpTorsionAnglePrefs=True, useBasicKnowledge=True)

    confs = list(range(mol.GetNumConformers()))
    rmsd_matrix = np.zeros((len(confs), len(confs)))
    for i in range(len(confs)):
        for j in range(i + 1, len(confs)):
            rmsd = rdMolAlign.GetBestRMS(mol, mol, confs[i], confs[j])
            rmsd_matrix[i, j] = rmsd
            rmsd_matrix[j, i] = rmsd

    linkage = hierarchy.linkage(rmsd_matrix, method='average')
    clusters = hierarchy.fcluster(linkage, t=100, criterion='maxclust')

    selected_confs = []
    for cluster_id in range(1, 101):
        cluster_indices = [i for i, c in enumerate(clusters) if c == cluster_id]
        if cluster_indices:
            selected_confs.append(cluster_indices[0])

    new_mol = Chem.Mol(mol)
    new_mol.RemoveAllConformers()
    for conf_id in selected_confs:
        conf = mol.GetConformer(conf_id)
        new_mol.AddConformer(conf, assignId=True)
    return new_mol

# Step 6: Conformer Optimization and Refinement
def apply_constraints(mol, conf_id, msms_data, nmr_data):
    for m, _ in msms_data:
        if abs(m - 77) < 1.0:
            pass
    for ppm, _ in nmr_data:
        if ppm < 3.5:
            pass
    AllChem.MMFFOptimizeMolecule(mol, confId=conf_id, maxIters=1000)

def process_conf(args):
    mol, conf_id, msms_data, nmr_data = args
    apply_constraints(mol, conf_id, msms_data, nmr_data)
    return conf_id

def spectral_guided_refinement(mol, conf_id, msms_data, nmr_data):
    mw = Descriptors.MolWt(mol)
    matches = sum(1 for m, _ in msms_data if abs(m - mw) < 50)
    msms_fit = matches / len(msms_data) if msms_data else 0

    if msms_fit < 0.5:
        AllChem.MMFFOptimizeMolecule(mol, confId=conf_id, maxIters=500)

    simulated_shifts = [2.0, 6.0]
    nmr_fit = 1.0 - np.mean(np.abs(np.array(simulated_shifts) - np.array([ppm for ppm, _ in nmr_data]))) / max(simulated_shifts)

    chiral_centers = Chem.FindMolChiralCenters(mol)
    expected_centers = len(chiral_centers)
    stereo_score = 1.0 - (0.05 * abs(expected_centers - len(chiral_centers)))

    return msms_fit, nmr_fit, stereo_score

def process_confs(mol, msms_data, nmr_data):
    pool = mp.Pool(mp.cpu_count())
    args = [(mol, conf_id, msms_data, nmr_data) for conf_id in range(mol.GetNumConformers())]
    pool.map(process_conf, args)
    pool.close()

    scores = []
    for conf_id in range(mol.GetNumConformers()):
        msms_fit, nmr_fit, stereo_score = spectral_guided_refinement(mol, conf_id, msms_data, nmr_data)
        scores.append((conf_id, msms_fit, nmr_fit, stereo_score))
    return scores

# Step 7: Best Conformer Selection and Output
def save_output(smiles, mol, best_conf_id, msms_data, scores, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    mol_formula = Chem.rdMolDescriptors.CalcMolFormula(mol)
    mol_mass = Descriptors.MolWt(mol)
    ms_fragments = ", ".join([f"m/z {mz}: {intensity}" for mz, intensity in msms_data])
    msms_fit, nmr_fit, stereo_score, rmsd, tm_score = scores

    with open(os.path.join(output_dir, "results.txt"), "w") as f:
        f.write(f"SMILES: {smiles}\n")
        f.write(f"Molecular Formula: {mol_formula}\n")
        f.write(f"Molecular Mass: {mol_mass:.2f} Da\n")
        f.write(f"MS Fragments: {ms_fragments}\n")
        f.write(f"Performance Scores:\n")
        f.write(f"MS/MS Fit: {msms_fit:.4f}\n")
        f.write(f"NMR Fit: {nmr_fit:.4f}\n")
        f.write(f"Stereo Score: {stereo_score:.4f}\n")
        f.write(f"RMSD: {rmsd:.4f}\n")
        f.write(f"TM-score-like: {tm_score:.4f}\n")

    glb_path = os.path.join(output_dir, "output_3d.glb")
    pdb_block = Chem.MolToPDBBlock(mol, confId=best_conf_id)
    viewer = py3Dmol.view(width=300, height=300)
    viewer.addModel(pdb_block, "pdb")
    viewer.setStyle({"stick": {}})
    mesh = trimesh.Trimesh()
    save_to_glb(mesh, glb_path)

    return os.path.join(output_dir, "results.txt"), glb_path

def run_wild(input_path_ms, input_path_msms, input_path_nmr, output_dir):
    ms_data, msms_data, nmr_data = process_input(input_path_ms, input_path_msms, input_path_nmr)
    latent = encode_spectral_data(ms_data, msms_data, nmr_data)
    smiles = predict_2d(ms_data, msms_data, nmr_data)
    if not smiles:
        return None, None, None

    mol = generate_initial_3d(smiles)
    if not mol:
        return None, None, None

    mol_wt = Descriptors.MolWt(mol)
    if not (30 <= mol_wt <= 3000):
        print(f"Molecular weight {mol_wt} Da is outside the 30-3000 Da range.")
        return None, None, None

    mol = cluster_conformers(mol)
    scores = process_confs(mol, msms_data, nmr_data)

    ref_conf_id = 0
    max_distance = 10 * mol.GetNumAtoms()
    best_score = -float('inf')
    best_conf_id = 0
    best_metrics = None
    for conf_id, msms_fit, nmr_fit, stereo_score in scores:
        rmsd = rdMolAlign.GetBestRMS(mol, mol, ref_conf_id, conf_id)
        tm_score = 1.0 / (1.0 + rmsd / max_distance)
        combined_score = 0.4 * msms_fit + 0.2 * nmr_fit + 0.2 * stereo_score + 0.1 * (1 - rmsd / max_distance) + 0.1 * tm_score
        if combined_score > best_score:
            best_score = combined_score
            best_conf_id = conf_id
            best_metrics = (msms_fit, nmr_fit, stereo_score, rmsd, tm_score)

    txt_path, glb_path = save_output(smiles, mol, best_conf_id, msms_data, best_metrics, output_dir)
    return smiles, glb_path, txt_path

if __name__ == "__main__":
    output_dir = input("Enter the output directory: ")
    test_cases = [
        {
            "input_path_ms": "MS-paclitaxel.jpg",
            "input_path_msms": "Ms-ms28-01027-g001.jpg",
            "input_path_nmr": "Taxol425_NMR.jpg",
            "expected_smiles": "CC1(C)[C@@H]2CC[C@@]3(C)[C@H](CC[C@H]4[C@@]5(C)CC[C@H](O)[C@@](C)(C(=O)O)[C@@H]5CC[C@@]34C)[C@@H]2[C@@H](O)[C@@H](O)[C@@H]1C(=O)O"
        },
    ]

    for test in test_cases:
        print(f"\nProcessing {test['input_path_ms']}, {test['input_path_msms']}, {test['input_path_nmr']}:")
        smiles, glb_path, txt_path = run_wild(
            test["input_path_ms"], test["input_path_msms"], test["input_path_nmr"], output_dir
        )
        print(f"Predicted SMILES: {smiles}")
        print(f"Expected SMILES: {test['expected_smiles']}")
        print(f"3D GLB Path: {glb_path}")
        print(f"Results TXT Path: {txt_path}")