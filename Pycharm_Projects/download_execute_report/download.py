#!/usr/env/bin python
import requests


def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)


download("https://s14415.pcdn.co/wp-content/resize/uploads/brandwatch/troll.jpg__w469")
