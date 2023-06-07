# host-check
Using machine learning to identify potential malware hostnames.

## Rationale
- Used github/StevenBlack's consolidated hostname blacklist as source of mallicious websites and Alexa's tracked top websites (100k in our case).
- Heavy feature engineering used to generated features out of only one feature - hostnames!
- Tested a suite of classifiers on the final scaled numeric features:
    - Logistic Regression
    - Naïve Bayes
    - K-Nearest Neighbours (k=5)
    - Random Forest
    - Stochastic Gradient Descent
- Narrowed down tuning with only a couple classifiers and tested a custom ensemble classifier with the tuned versions using soft voting.

## Results
- **~84%** accuracy when using features (with weight > 0.01)
    - **~79%** accuracy with only **3** features! (signifcantly less time required for feature engineering)
- Further improvements can be made using deep learning and/or trying different feature extractions

## How to deploy
### Create conda environment
- run `conda env create -f resources/host-check.yml`
### Replicate results only
- Unzip `resources\df_final.zip` and `resources\random_forest_final.zip`
- Load the pickles to your own project and split test data using `train_test_split(X, y, test_size=0.2, random_state=42)` where `X = df.drop(['malicious'], axis=1` and `y = df['malicious']`
- Test the model against the above split or with your own data!
### Start from scratch*
- Unzip all zip files in `resources` folder (skip `.pickle.zip` files if not using)
    - Optionally skip the input files and fetch the latest versions:
        - `alexa` (unzip the downloaded file) - http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
        - `malware_pd` (rename to .csv as preference) - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
- Use `host-check.py` file and update paths for the above files if downloaded from the above links
- Run the file in command line using `python host-check.py` from conda prompt of your environment (should be `host-check`)
### TODO: Pipeline
- Using the learnings from the evaluation in `host-check.py`, will create a pipeline to feed fresh versions of `alexa` and `malware_pd` directly to the pieline and evaluate performance.
    - Optionally with grid search built-in! (although with heavy computational load!)

## References
- StevenBlack hosts file to blacklist malicious websites - https://github.com/StevenBlack/hosts
- Project on extracting features from URLs - https://github.com/lucasayres/url-feature-extractor
- Calculating Shannon Entropy on hostnames - https://web.archive.org/web/20210302232012/https://kldavenport.com/detecting-randomly-generated-domains/
