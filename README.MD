## Installation steps

1. Make sure you have Python installed (v3.11 or later). Download instructions [here](https://www.python.org/downloads/).

2. Clone this repository (for example on Desktop. Feel free to replace Desktop with your preferred folder.)

```bash
cd Desktop
git clone https://github.com/chhpy/simple-SHA256-encoder-and-checker
cd simple-SHA256-encoder-and-checker
```

3. (optional) Create a virtual environment and install the project's requirements there. *This is not needed in the current version.*
```bash
python3 -m venv .venv
source .venv/bin/activate
```
(optional) Install requirements. *This is not needed in the current version.* Currently the project does not have any dependencies, so nothing will be installed.
```bash
pip install -r requirements.txt
```

4. Run the app
```bash
python3 app.py
```

## How to use the app
***Save the original salt and the original hashed message. Both are needed in case you want to check/validate the message at a later date.***
1.  Browse through the menu depeinding on your needs. The script can generate *salted* and *non-salted* hashes, and check for both. 
2.  If you want to encode a message and salt it, the script will generate a random salt and apply it before your text. 
3.  The script will print the salt in hex form, as well as the hashed message
4.  For copying and pasting from the terminal you should use <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> and <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>V</kbd>
5.  If you want to check a message, you will need the original salt in hex form (if applicable) as well as the original hashed message. The script will then check and show a message if your input matches the pasted hashed message. 
