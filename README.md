## FurryFriends website quick deployment guide

* Web application link: http://4.221.14.161/

An automation script for automatically deploying changes to a VM after uploading them to GitHub.

## Features

* Check code differences

* Automatically deploy code to VM

## Install

* Clone this repository
    <!-- VS Code is recommended. -->

    ```bash
        git clone https://github.com/Nyashiko/furry-friend.git
        ```


* Ensure that the following software is installed on your system.

    Node.js (v18.0.0 or later)

    Python (v3.8 or later)

    Docker (v20.0 or later)

    Git (v2.25 or later)

    Use the following commands to check.
    ```bash
    pip install -r requirements.txt
    ```

* Copy the environment variable file
    cp .env.example .env

* Edit the environment variable configuration

    nano .env 
    <!-- or use your preferred editor -->

* Start the development server

    python app.py

    export FLASK_APP=app.py
    flask run

# Automatic code deployment to VM

1. After modifying the code in VSCode, save all files.

2. Add changes to the staging area.

    git add .

3. Commit the changes (make the commit message clear).

    git commit -m "feat:

4. Push to GitHub to trigger automatic deployment.

    git push origin main

# Simply refresh the website page after a few seconds.