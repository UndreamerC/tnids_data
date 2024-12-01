#!/usr/bin/env python
# coding: utf-8

# In[13]:


import os
import requests
from bs4 import BeautifulSoup


# In[14]:


# 设置基本URL
base_url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-"

# 定义每组数据集编号以及对应的文件夹名称
dataset_groups = {
    "Artemis": [275, 305, 306, 311, 316, 374],
    "Trickster": [277, 302, 309, 323],
    "TrickBot": [238, 239, 240, 241, 242, 243, 244, 247, 261.1, 261.2,
261.3, 261.4, 265, 266, 267, 273, 324, 325, 327.1, 327.2, 405],
    "WannaCry":[ 252, 253, 254, 256, 258, 270, 283, 284, 285, 286,
287, 290, 291, 292, 293, 294, 295, 296, 297],
    "Dridex.A": [218, 228, 248, 249, 251, 257, 259, 260, 263, 322,
326, 346]
}

# 基本下载目录
base_download_dir = "./mcfp"
os.makedirs(base_download_dir, exist_ok=True)


# In[15]:


def get_pcap_links(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 查找所有以'.pcap'结尾的文件
        pcap_links = [url + link.get('href') for link in soup.find_all('a', href=True) if link.get('href').endswith('.pcap')]
        return pcap_links
    except requests.exceptions.RequestException as e:
        print(f"Failed to access {url}: {e}")
        return []

def download_file(url, folder):
    local_filename = os.path.join(folder, url.split('/')[-1])
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Downloaded: {local_filename}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download {url}: {e}")


# In[16]:


def format_id(dataset_id):
    """将编号转换为指定格式，如1为1-1，20.1为20-1"""
    if isinstance(dataset_id, float):
        main_part, sub_part = str(dataset_id).split(".")
        return f"{main_part}-{sub_part}"
    return f"{int(dataset_id)}-1"


# In[ ]:


for group_name, dataset_ids in dataset_groups.items():
    group_dir = os.path.join(base_download_dir, group_name)
    os.makedirs(group_dir, exist_ok=True)
    
    # 遍历每个数据集编号并下载.pcap文件
    for dataset_id in dataset_ids:
        formatted_id = format_id(dataset_id)
        link = f"{base_url}{formatted_id}/"
        print(f"Accessing: {link}")
        
        pcap_files = get_pcap_links(link)
        for pcap_file in pcap_files:
            download_file(pcap_file, group_dir)

print("所有文件下载完成。")

