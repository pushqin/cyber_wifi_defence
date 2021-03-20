# cyber_wifi_defence

**  ENvironment

We dont want to pollute our environement, if you dont care go to step 2

*** Step 1 - Setup virtual environment
Install venv -   ```apt-get install python3-venv```
Create venv  ```python3 -m venv wifi-deauth```
Activate environemnt ```source wifi-deauth/bin/activate```


*** Ste 2 - Install requirements
run ```pip install -r requirements.txt```


*** Step 3 - Activate monitoring
Set value `wlan1` of interfaces according to your environment
```iw dev wlan1 interface add wlan0mon type monitor```
```ifconfig wlan0mon up```

*** Scan for access points

