# Wireless Intrusion Detection (WIDS/WIPS) with Machine Learning

This project detects Wi-Fi deauthentication flood attacks with a Random Forest classifier. It splits Wi-Fi traffic into one-second windows, calculates six traffic features for each window, and predicts whether each window is normal or an attack.

The repository includes a pretrained model (`wids_model.joblib`). The detector reads a packet capture, prints a line for every second (normal or `[ALERT]`), and, as the WIPS action, logs the top deauthentication sender's MAC address to `blocklist.log`. It does **not** configure a firewall or block traffic on a real network.

## Results at a glance

| Test                                                            | Data                                            | Windows | Accuracy |
| --------------------------------------------------------------- | ----------------------------------------------- | ------- | -------- |
| Random 70/30 holdout                                            | WPA3 Attacks Dataset (same capture as training) | 276     | 100%     |
| Time-based holdout, no deauth-count features (diagnostic model) | WPA3 Attacks Dataset                            | 276     | 98.9%    |
| Cross-dataset, no retraining                                    | AWID3 (never seen in training)                  | 603     | 99.3%    |

## Project layout

```
.
├── README.md
├── WIDS Poster.pdf
├── WPA3 Attacks Dataset/
│   └── WPA3 Denial of Service attacks/
│       └── Deauthentication attack/
│           ├── train.py                         # builds features, trains and saves the model
│           ├── detector.py                      # replays a pcap, raises alerts, logs MACs
│           ├── wids_model.joblib                # pretrained Random Forest
│           ├── CM_WPA3_test.png
│           ├── CM_WPA3_timesplit_no_deauth.png
│           ├── Deauth.csv                       # from the dataset (not in the repo)
│           └── Deauth.pcap                      # from the dataset (not in the repo)
└── AWID3_Dataset_CSV/
    └── CSV/
        └── 1.Deauth/
            ├── eval_awid3.py                    # tests the saved model on AWID3
            ├── wids_model.joblib                # copy of the pretrained model
            ├── CM_AWID3_test.png
            └── Deauth_0.csv ... Deauth_32.csv   # from AWID3 (not in the repo)
```

## Requirements

Install Python 3 and the dependencies:

```bash
python -m pip install pandas matplotlib joblib scikit-learn scapy
```

On Windows, use `py` in place of `python` if `python` is not recognised (for example `py -m pip install ...` and `py train.py`).

Run each script from the directory that contains it. The scripts use paths relative to the current working directory.

## Get the data

The datasets are large and are not included in the repository.

### WPA3 Attacks Dataset (training and detector demo)

1. Download the [WPA3 Attacks Dataset from Mendeley Data](https://data.mendeley.com/datasets/cxx5t5nw7z/1).
2. From the download, copy `Deauth.csv` and `Deauth.pcap` out of `WPA3 Denial of Service attacks/Deauthentication attack/`.
3. Place both files in `WPA3 Attacks Dataset/WPA3 Denial of Service attacks/Deauthentication attack/` in this repository.

Both files come with the dataset, so no conversion or labelling is needed. Only these two files are used; the other attack folders in the dataset are not.

### AWID3 (independent test)

See [Evaluate on AWID3](#evaluate-on-awid3) below.

## Run the pretrained detector

From the `Deauthentication attack` directory, pass a PCAP containing 802.11 frames with radiotap headers (monitor-mode capture):

```bash
cd "WPA3 Attacks Dataset/WPA3 Denial of Service attacks/Deauthentication attack"
python detector.py path/to/capture.pcap
```

### Demo on the WPA3 capture

In `Deauth.pcap`, the deauthentication flood runs from second 367 to second 737. To show the switch from normal traffic to an attack:

```bash
python detector.py Deauth.pcap --start 360 --seconds 20
```

Add `--live` to pause one second after each window, so the output appears at real-time pace:

```bash
python detector.py Deauth.pcap --start 360 --seconds 20 --live
```

Expected output (shortened):

```
t=365s normal (513 frames)
t=366s normal (561 frames)
[ALERT] t=367s deauth flood: 407 deauth frames, top sender 02:00:00:00:00:cb
[WIPS] logged 02:00:00:00:00:cb to blocklist.log
[ALERT] t=368s deauth flood: 286 deauth frames, top sender 02:00:00:00:00:72
[WIPS] logged 02:00:00:00:00:72 to blocklist.log
[ALERT] t=369s deauth flood: 273 deauth frames, top sender 02:00:00:00:00:72
...
```

Then view the log:

```bash
type blocklist.log      # Windows
cat blocklist.log       # Linux / macOS
```

### Options

| Option      | Meaning                                         | Default |
| ----------- | ----------------------------------------------- | ------- |
| `pcap`      | Path to the capture file (required)             |         |
| `--start`   | Offset in seconds from the start of the capture | `0`     |
| `--seconds` | Maximum number of seconds to process            | `60`    |
| `--live`    | Pause one second after each window              | off     |

### How the detector works

1. Reads the capture packet by packet with Scapy and keeps only 802.11 frames.
2. Groups frames into one-second windows by timestamp.
3. For each window, calculates the same six features used in training: total frames, deauthentication frames (type 0, subtype 12), deauthentication ratio, average signal strength (dBm), average frame length, and retry ratio.
4. Passes the features to the saved Random Forest (`wids_model.joblib`).
5. If the window is predicted as an attack, prints an `[ALERT]` line and appends the top deauthentication sender's MAC address to `blocklist.log`. Each MAC is logged once per run.

### Notes

- `blocklist.log` is appended to on every run. Delete it before a demo for a clean log (`del blocklist.log` on Windows, `rm blocklist.log` on Linux/macOS).
- `--start` still reads every packet before the start point, so a large start offset on a big capture takes a while before output appears.
- If a capture has no signal-strength data, the detector uses `-60` dBm as a fallback. Results on such captures are less reliable.
- The detector replays recorded captures; it does not sniff live traffic.

## Train the model

### Training data

`Deauth.csv` must be in the `Deauthentication attack` directory (see [Get the data](#get-the-data)). The script reads these columns:

- `frame.time_relative`
- `frame.len`
- `radiotap.dbm_antsignal`
- `wlan.fc.type_subtype`
- `wlan.fc.retry`
- `Label` (values `Normal` or `Deauth`)

### Training procedure

```bash
cd "WPA3 Attacks Dataset/WPA3 Denial of Service attacks/Deauthentication attack"
python train.py
```

The script does the following:

1. **Loads** the six columns above from `Deauth.csv` (722,606 frames).
2. **Windows** the frames into one-second windows using `frame.time_relative` (917 windows).
3. **Extracts features** per window: total frame count, deauthentication frame count (`wlan.fc.type_subtype == 12`), deauthentication ratio, average signal strength, average frame length, and retry ratio. Missing values are filled with each feature's median.
4. **Labels** each window: a window is an attack if it contains at least one frame the dataset labels `Deauth`. This gives 546 normal and 371 attack windows.
5. **Trains the main model**: a 100-tree Random Forest on a stratified random 70/30 split (`random_state=42`), and reports accuracy and a classification report on the 30% test set.
6. **Saves** the model as `wids_model.joblib`, the feature table as `features.csv`, and the confusion matrix as `CM_WPA3_test.png`.
7. **Runs a diagnostic check**: a separate Random Forest trained on the first 70% of windows and tested on the last 30%, without the deauthentication count and ratio features. This only shows whether the other traffic features also change during an attack. It does not replace the saved model. Its confusion matrix is saved as `CM_WPA3_timesplit_no_deauth.png`.

Expected console output (shortened):

```
Windows: 917
label
0    546
1    371

=== Detector (all features) ===
Accuracy: 1.0
...
=== Time-based split, no deauth features ===
Accuracy: 0.9891304347826086
[[177   2]
 [  1  96]]
```

Because `random_state=42` is fixed, retraining on the same data produces the same model.

## Evaluate on AWID3

The AWID3 CSVs are large and are not included in this repository. Download them from the [official AWID website](https://icsdweb.aegean.gr/awid/):

1. Open the [AWID dataset download page](https://icsdweb.aegean.gr/awid/download) and submit a request using a valid university or organisation email. Include the requested justification and select the AWID3 CSV dataset.
2. Confirm the request using the link sent to your email. The request is not registered until you confirm it; the confirmation expires after 48 hours.
3. After approval, follow the separate download email. Download the **AWID3-CSV** data, not only the raw PCAP files: `eval_awid3.py` reads CSVs and does not convert PCAPs.
4. Extract the AWID3 **Deauth** CSV files into `AWID3_Dataset_CSV/CSV/1.Deauth` in the repository. Put the files directly in that directory, named `Deauth_0.csv` to `Deauth_32.csv`.

The evaluator combines all `Deauth_*.csv` files in that directory, in numeric order. It reads these columns: `frame.time_epoch`, `wlan.fc.type`, `wlan.fc.subtype`, `frame.len`, `radiotap.dbm_antsignal`, `wlan.fc.retry`, and `Label`. Rows whose `Label` is exactly `Deauth` count as attack frames. The attack frames are in `Deauth_21.csv` to `Deauth_32.csv`; the earlier files contain only normal traffic, but all files are needed to build the full timeline.

The repository includes the trained model in both directories. If you retrain the WPA3 model and want to evaluate the new model on AWID3, copy it into the AWID3 directory first (run this from `AWID3_Dataset_CSV/CSV/1.Deauth`):

```bash
python -c "import shutil; shutil.copyfile(r'../../../WPA3 Attacks Dataset/WPA3 Denial of Service attacks/Deauthentication attack/wids_model.joblib', 'wids_model.joblib')"
```

Then run the evaluation from the AWID3 directory:

```bash
cd "AWID3_Dataset_CSV/CSV/1.Deauth"
python eval_awid3.py
```

The script has no command-line arguments and takes a minute or two (about 1.6 million rows). It builds the same one-second features as `train.py`, applies the saved model without retraining, reports accuracy and a classification report, lists the misclassified windows, and saves `features_awid3.csv` and `CM_AWID3_test.png` in the current directory.

## Confusion matrices

Each matrix counts one-second windows. The vertical axis is what actually happened (the dataset's label) and the horizontal axis is the model's prediction. The colour bar only shades each box by its count: bright means many windows, dark means few.

| Cell         | Meaning                                                         |
| ------------ | --------------------------------------------------------------- |
| Top-left     | Normal windows correctly predicted as normal                    |
| Top-right    | Normal windows incorrectly flagged as attacks (false alarms)    |
| Bottom-left  | Attack windows incorrectly predicted as normal (missed attacks) |
| Bottom-right | Attack windows correctly detected                               |

### WPA3 random holdout

![WPA3 random 70/30 holdout confusion matrix](WPA3%20Attacks%20Dataset/WPA3%20Denial%20of%20Service%20attacks/Deauthentication%20attack/CM_WPA3_test.png)

The main Random Forest on the randomly held-out 30% of WPA3 windows: 164 normal and 112 attack windows correctly classified, with no errors (100% accuracy). This result is expected rather than impressive: normal traffic in this capture contains no deauthentication frames, so the deauthentication count alone separates the classes. Because the split is random across windows from the same capture, it is not an independent-network test.

### WPA3 time-based holdout without deauthentication-count features

![WPA3 time-based holdout without deauthentication-count features](WPA3%20Attacks%20Dataset/WPA3%20Denial%20of%20Service%20attacks/Deauthentication%20attack/CM_WPA3_timesplit_no_deauth.png)

The separate diagnostic model, trained on the first 70% of the capture and tested on the last 30%, without the deauthentication count or ratio. It correctly classified 177 normal and 96 attack windows, raised 2 false alarms, and missed 1 attack (98.9% accuracy). This shows that frame volume, frame size, signal strength and retries also change noticeably during the attack.

### AWID3 cross-dataset evaluation

![WPA3-trained model evaluated on AWID3](AWID3_Dataset_CSV/CSV/1.Deauth/CM_AWID3_test.png)

The saved WPA3 model on 603 AWID3 windows, without retraining. It correctly classified 423 normal and 176 attack windows, raised no false alarms, and missed 4 attacks (99.3% accuracy). The 4 missed windows had only 45 to 78 deauthentication frames per second, while the slowest attack second in the training data had 106. This measures performance on this AWID3 export; it is not a guarantee of performance on other networks or captures.

## Limitations

- **Few harmless deauthentication frames:** normal traffic contained 0 deauthentication frames in the WPA3 capture and 3 in AWID3, so false alarms on a busy real network, where clients leaving or roaming send some, are untested.
- **Slow floods:** floods slower than anything in the training data can be missed, as the 4 AWID3 misses show.
- **Spoofed senders:** the logged MAC addresses are locally administered (`02:...`) addresses. Attackers can forge the sender, so blocking by MAC could block the legitimate access point.
- **Replay, not live capture:** no monitor-mode Wi-Fi adapter was available, so the detector was demonstrated on recorded captures.

## Possible improvements

- Train on both datasets together so the model sees slower floods and heavier background traffic.
- Capture live traffic in monitor mode on an authorised lab network.
- Detect disassociation and beacon flood attacks as well.
- Enable Protected Management Frames (802.11w), which WPA3 requires, as the real defence against forged deauthentication frames.

## Troubleshooting

- **`ModuleNotFoundError`:** install the requirements (see [Requirements](#requirements)).
- **`FileNotFoundError` for `Deauth.csv`, `Deauth.pcap` or `wids_model.joblib`:** run the script from the directory that contains the file, or check the file is there.
- **Error or warning when loading `wids_model.joblib`:** the saved model can depend on the scikit-learn version. Retrain it with `python train.py`, then copy the new model to the AWID3 directory.

## Use of AI

I used Claude (Anthropic) as a coding assistant to plan the build, draft `train.py`, `detector.py`, and `eval_awid3.py`, and debug errors. I ran every step myself, checked results against the dataset labels, and can explain how each part of the code works. I also used Claude (Anthropic) to help design the poster.

## Poster

[A1 poster: Catching the deauth flood (PDF)](WIDS%20Poster.pdf)
