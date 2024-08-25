# bbx

## Install

1. Download code
```
git clone https://gitlab.mitre.org/BB-ATE/bbx.git
```

2. (optional) Setup virtual environment
```
python3 -m venv bbx_env
source bbx_env/bin/activate
```

3. Install requirements
```
cd bbx
pip install -r requirements.txt
```

## Running BBX

Run BBX with the default config and CASCADE and whitelist rules:
```
cd bbx
python ./bbx.py -c ../config/default.yml -r ../config/cascade_rules.yml ../config/whitelist_rules.yml
```
