import re
import hashlib
import numpy as np
from json import load, dump
import os
import tokenizer as tk
from urllib.parse import urlparse, urljoin, urldefrag

from bs4 import BeautifulSoup

# param to check if we just started crawling
# URL_MAXLEN = 225
# SEGMENTS_MAXLEN = 10
# QUERY_PARAMS_MAXLEN = 5
#SIMHASH_THRESHOLD = 6  # Max Hamming distance for duplicates

MAX_FILE_SIZE = 10 * 1024 * 1024 
MIN_FILE_SIZE = 500


class SimHash:
    def __init__(self, hash_size=64):
        self.hash_size = hash_size

    def _hash(self, token):
        """Hash a token into a fixed-size integer."""
        return int(hashlib.md5(token.encode()).hexdigest(), 16) & ((1 << self.hash_size) - 1)

    # CHATGBT CODE FOR A LIGHT-WEIGHT HASHER, LOW PRIORITY NGL
    # def _hash(self, token):
    #     """Hash a token into a fixed-size integer using Python's built-in hash."""
    #     return hash(token) & ((1 << self.hash_size) - 1)

    def compute(self, text):
        # EDGE CASE IF TEXT IS EMPTY
        # if not text:
        #     return 0  # Return 0 for empty input

        """Compute the SimHash fingerprint of the input text."""
        tokens = tk.tokenize(text)  # Simple tokenization by whitespace
        vector = np.zeros(self.hash_size)

        for token in tokens:
            token_hash = self._hash(token)
            for i in range(self.hash_size):
                bit = (token_hash >> i) & 1
                vector[i] += 1 if bit else -1

        # Convert vector to final hash
        fingerprint = 0
        for i in range(self.hash_size):
            if vector[i] > 0:
                fingerprint |= (1 << i)

        return fingerprint

    def hamming_distance(self, hash1, hash2):
        """Compute the Hamming distance between two hash values."""
        return bin(hash1 ^ hash2).count('1')


simhash = SimHash()


def scraper(url, resp, visited_urls):
    try:
        # Attempt to extract next links from the response
        links = extract_next_links(url, resp, visited_urls)
        # Filter valid links based on the is_valid check
        valid_links = [link for link in links if is_valid(link)]
        return valid_links

    except Exception as e:
        print(f"Error in scraper for URL {url}: {e}")
        return []


#testtestestestststststststestsetts


def jsonStats(soup_text, url):
    word_list = tk.tokenize(soup_text)
    word_count = len(word_list)
    webtokens = tk.computeWordFrequencies(word_list)
    webPageFreq = {url: word_count}
    subdomain = extract_subdomain(url)

    simhash_value = simhash.compute(soup_text)

    if not os.path.exists("crawlerStat.json"):
        with open("crawlerStat.json", "w") as jsonFile:
            dump([webtokens, webPageFreq, {subdomain: 1}, {url: simhash_value}], jsonFile, indent=4, ensure_ascii=False)

    else:
        with open("crawlerStat.json", "r", encoding="utf-8") as jsonFile:
            jsonDicts = load(jsonFile)
            jsonFreq, jsonWebPage, jsonSubDomain, jsonSimhashes = jsonDicts

            duplicate_found = any(
                simhash.hamming_distance(existing_simhash, simhash_value) <= 6
                for existing_simhash in jsonSimhashes.values()
            )

            if duplicate_found:
                return False

            for key, value in webtokens.items():
                jsonFreq[key] = jsonFreq.get(key, 0) + value

            if subdomain in jsonSubDomain:
                jsonSubDomain[subdomain] += 1
            else:
                jsonSubDomain[subdomain] = 1

            jsonWebPage.update(webPageFreq)
            jsonSimhashes[url] = simhash_value

        with open("crawlerStat.json", "w", encoding="utf-8") as jsonFile:
            dump([jsonFreq, jsonWebPage, jsonSubDomain, jsonSimhashes], jsonFile, indent=4, ensure_ascii=False)

    return True


def extract_next_links(url, resp, visited_urls, max_redirects=5):
    if 300 <= resp.status < 400:
        redirected_url = resp.raw_response.headers.get("Location")
        if redirected_url:
            redirected_url = urljoin(url, redirected_url)  # Handle relative redirects

            # Check if we've already visited this redirected URL to avoid infinite loops
            if redirected_url in visited_urls:
                print(f"Skipping {redirected_url} (Already visited, avoiding infinite redirect loop)")
                return []

            return [redirected_url]

    if resp.status == 200:
        # soup class/html parser from external lib, download dependencies using install command from website below
        # https://www.crummy.com/software/BeautifulSoup/bs4/doc/

        content_length = len(resp.raw_response.content)
        if content_length > MAX_FILE_SIZE:
            print(f"Skipping {url} (File too large: {content_length} bytes)")
            return []

        if content_length < MIN_FILE_SIZE:
            print(f"Skipping {url} (File too small: {content_length} bytes)")
            return []

        try:
            soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        except Exception as e:
            print(f"Error parsing page {url}: {e}")
            return []

        scraped_links = soup.find_all('a')
        links = [urljoin(url, urldefrag(link.get('href')).url)
                 for link in scraped_links if link.get('href')]
        print(f"Extracted {len(links)} links.")

        if not (jsonStats(soup.get_text(), url)):
            return []
        # # UPDATE JSON WITH

        # LONGEST WEBPAGE (URL, WORD_COUNT)
        # UPDATE DICTIONARY OF WORDS (WEBTOKENS)
        # UPDATE SUBDOMAIN CRAWLED

        return links
    print(resp.error)  # only prints if an error status was found
    return list()


def extract_subdomain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    parts = domain.split('.')

    # Extract subdomain
    if len(parts) > 2:
        return '.'.join(parts[:-2])  # Gives subdomain part

    # null return, worried might mess with subdomain storing
    # return None # no subdomains found


# uci domains only alloweddddd
ALLOWED_DOMAINS = {
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu",
}

def is_allowed_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc  # Extracting domain

    # Check if the domain ends with any of the allowed suffixes
    for allowed_domain in ALLOWED_DOMAINS:
        if domain.endswith(allowed_domain):
            return True
    return False


def is_allowed_path(url):
    BANNED_PATH = {
        "/events/",
        "/pdf/"
    }

    path = urlparse(url).path
    for banned_paths in BANNED_PATH:
        if path == banned_paths:
            return False
    return True


def is_trap(url):
    trap_patterns = [
        r'\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b',
        r'\b\d{4}[-/]\d{2}(-\d{2})?\b',
        r'[?&](date|year|month|day|view|do|tab_files|ical)=[^&]*',
        r'gitlab\.ics\.uci\.edu.*/(-/|users/|blob/|commits/|tree/|compare|explore/|\.git$|/[^/]+/[^/]+)',
        r'sli\.ics\.uci\.edu.*\?action=download&upname=',
        r'wp-login\.php\?redirect_to=[^&]+',
        r'/page/\d+',
        r'[\?&]version=\d+',
        r'[\?&]action=diff&version=\d+',
        r'[\?&]format=txt',
        r'\b\d{4}-(spring|summer|fall|winter)\b'
    ]

    return any(re.search(pattern, url) for pattern in trap_patterns)


def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)

        if parsed.scheme in ("http", "https", "ftp", "ftps", "ws", "wss", "sftp", "smb") and not parsed.netloc:
            return False

        # Check if the domain is allowed
        if not is_allowed_domain(url):
            return False

        # CURRENTLY COMMENTED OUT CAUSE UNSURE IF IT WORKS AS INTENDED
        # Check if the path is allowed (avoiding junk paths like calendars)
        if not is_allowed_path(url):
            return False

        # Trap detection
        if re.search(r'/page/\d+', url):
            return False
        if re.search(r'[\?&]version=\d+', url) or re.search(r'[\?&]action=diff&version=\d+', url):
            return False
        if is_trap(url):
            return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz|war|apk|img|sql)$", parsed.path.lower())

    except TypeError as e:
        print("TypeError for ", e)
        raise
