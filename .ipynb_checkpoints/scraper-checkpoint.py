import re
from urllib.parse import urlparse, urldefrag
from bs4 import BeautifulSoup

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    if resp.status == 200:
        # soup class/html parser from external lib, download dependencies using install command from website below
        # https://www.crummy.com/software/BeautifulSoup/bs4/doc/
        soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
        scraped_links = soup.find_all('a')
        links = [urldefrag(link.get('href')).url for link in scraped_links if link.get('href')]

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

def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl, return True; otherwise return False.
    # There are already some conditions that return False.
    def is_valid(url):
        # Decide whether to crawl this url or not.
        # If you decide to crawl it, return True; otherwise return False.
        # There are already some conditions that return False.
        try:
            parsed = urlparse(url)

            if not re.match(r"[a-zA-Z][[a-zA-Z0-9+.-]*]", parsed.scheme):
                return False

            if parsed.scheme in ("http", "https", "ftp", "ftps", "ws", "wss", "sftp", "smb") and not parsed.netloc:
                return False

            return not re.match(
                r".*\.(css|js|bmp|gif|jpe?g|ico"
                + r"|png|tiff?|mid|mp2|mp3|mp4"
                + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
                + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
                + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
                + r"|epub|dll|cnf|tgz|sha1"
                + r"|thmx|mso|arff|rtf|jar|csv"
                + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

        except TypeError as e:
            print("TypeError for ", e)
            raise
gi
