# Deauth attack - Course Asignments

#### Summary and notes ####
* Tested on 2.4 GHz,not sure about 5Ghz
* The code tested with TL-WN722N from labaratory, deauthentication made on private huawei phone that connected to bezeq Vtech router,didnt tested on neighbours :-)
* On some day working code just stopped finding connected stations of access point,wasted on that whole day and tomorrow it magically started to work again, the frustrating part is that there is no clue why it didnt work.
* Some of the code is taken from various places on the web, modified to be as it now.
* Accidentaly run kali as root(bad practice), so i hope everything will work properly on least previledged account as well.

#### Requirements ####
```python 3.9``` Comes with *kali* latest distribution,that installed as dual boot,so  the code is not tested on lower python versions


### Usage ###


#### Step 1 - Clone the repo

#### Step 2 - Setup virtual environment
We dont want to pollute our environement, if you dont care go to **step 2**

Install venv -   ```apt-get install python3-venv```
Create venv  ```python3 -m venv wifi-deauth```
Activate environemnt ```source wifi-deauth/bin/activate```


#### Step 2 - Install requirements
run ```pip install -r requirements.txt```


#### Step 3 - Activate monitoring
Set value `wlan1` interface according to your environment
```iw dev wlan1 interface add wlan0mon type monitor```
```ifconfig wlan0mon up```


#### Step 4 - Run the main programm and follow instructions
```python3 main.py```



### Troubleshooting 

**Problem:** 
```No such file or directory: b'liblibc.a'``` this problem occures on python 3.9+   
**Solution:** 
```cd /usr/lib/x86_64-linux-gnu/```
```ln -s -f libc.a liblibc.a```