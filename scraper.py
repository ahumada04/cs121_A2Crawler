import re
import hashlib
import numpy as np
from json import load, dump
import os
import tokenizer as tk
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin, urldefrag

from bs4 import BeautifulSoup

# param to check if we just started crawling
# URL_MAXLEN = 225
# SEGMENTS_MAXLEN = 10
# QUERY_PARAMS_MAXLEN = 5
#SIMHASH_THRESHOLD = 6  # Max Hamming distance for duplicates
class SimHash:
    def __init__(self, hash_size=64):
        self.hash_size = hash_size

    def _hash(self, token):
        """Hash a token into a fixed-size integer."""
        return int(hashlib.md5(token.encode()).hexdigest(), 16) & ((1 << self.hash_size) - 1)

    def compute(self, text):
        """Compute the SimHash fingerprint of the input text."""
        tokens = text.split()  # Simple tokenization by whitespace
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

    def is_near_duplicate(self, content1, content2, threshold=6):  # 90% similarity
        """Check if two contents are near-duplicates using SimHash."""
        hash1 = self.compute(content1)
        hash2 = self.compute(content2)
        return self.hamming_distance(hash1, hash2) <= threshold


simhash = SimHash()


def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


# def canonicalize(url):
#     parsed = urlparse(url)
#
#     scheme = parsed.scheme
#     netloc = parsed.netloc
#
#     IGNORE_PARAMS = {"ical", "outlook-ical"}
#     filtered_query = [(key, value) for key, value in parse_qsl(parsed.query) if key not in IGNORE_PARAMS]
#     query = urlencode(sorted(filtered_query))
#
#     path = parsed.path
#     if path != "/" and path.endswith("/"):
#         path = path[:-1]
#
#     fragment = ""  # Remove fragment identifiers
#
#     canonical_url = urlunparse((scheme, netloc, path, "", query, fragment))
#     return canonical_url

#testtestestestststststststestsetts

def jsonStats(word_list, url):
    word_count = len(word_list)
    webtokens = tk.computeWordFrequencies(word_list)
    webPageFreq = {url: word_count}
    subdomain = extract_subdomain(url)
    simhash_value = simhash.compute(word_list)

    if not os.path.exists("crawlerStat.json"):
        with open("crawlerStat.json", "w") as jsonFile:
            dump([webtokens, webPageFreq, {subdomain: 1}, {url: simhash_value}], jsonFile, indent=4, ensure_ascii=False)

    else:
        with open("crawlerStat.json", "r+", encoding="utf-8") as jsonFile:
            jsonDicts = load(jsonFile)
            jsonFreq, jsonWebPage, jsonSubDomain, jsonSimhashes = jsonDicts

            duplicate_found = any(
                simhash.is_near_duplicate(existing_simhash, simhash_value)
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

            jsonFile.seek(0)
            jsonFile.truncate()
            dump([jsonFreq, jsonWebPage, jsonSubDomain, jsonSimhashes], jsonFile, indent=4, ensure_ascii=False)

    return True


def extract_next_links(url, resp):
    if resp.status == 200:
        # soup class/html parser from external lib, download dependencies using install command from website below
        # https://www.crummy.com/software/BeautifulSoup/bs4/doc/
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        scraped_links = soup.find_all('a')
        links = [urljoin(url, urldefrag(link.get('href')).url)
                 for link in scraped_links if link.get('href')]
        print(f"Extracted {len(links)} links.")

        word_list = tk.tokenize(soup.get_text())

        if not (jsonStats(word_list, url)):
            return []
        # # UPDATE JSON WITH

        # LONGEST WEBPAGE (URL, WORD_COUNT)
        # UPDATE DICTIONARY OF WORDS (WEBTOKENS)
        # UPDATE SUBDOMAIN CRAWLED

        return links

    # KEEPING COMMENTS BELOW ON PURPOSE !!!!!!!!!!!!!!!!!!!!!

    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content


    print(resp.error)  # only prints if an error status was found
    return list()


def extract_subdomain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    parts = domain.split('.')

    # Extract subdomain
    if len(parts) > 2:
        return '.'.join(parts[:-2])  # Gives subdomain part
    return subdomain


# uci domains only allowed
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


# list of paths TO AVOID
# update as we go
BANNED_PATH = {
    "/events/",
    "/pdf/"
    # ....
}


def is_allowed_path(url):
    path = urlparse(url).path
    # Check if the path is in any of the banned pathes
    for banned_paths in BANNED_PATH:
        if path == banned_paths:
            return False
    return True


def is_valid(url):
    # Decide whether to crawl this url or not.
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)

        if parsed.scheme in ("http", "https", "ftp", "ftps", "ws", "wss", "sftp", "smb") and not parsed.netloc:
            return False

        if not re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*", parsed.scheme):
            return False

        # Check if the domain is allowed
        if not is_allowed_domain(url):
            return False

        # CURRENTLY COMMENTED OUT CAUSE UNSURE IF IT WORKS AS INTENDED
        # Check if the path is allowed (avoiding junk paths like calendars)
        if not is_allowed_path(parsed.netloc):
            return False

        if parsed.scheme in ("http", "https", "ftp", "ftps", "ws", "wss", "sftp", "smb") and not parsed.netloc:
            return False

        # Trap detection
        if re.search(r'/page/\d+', url):
            return False
        if re.search(r'[\?&]version=\d+', url) or re.search(r'[\?&]action=diff&version=\d+', url):
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

