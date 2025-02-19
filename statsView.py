import sys
import json
from urllib.parse import urlparse


commands = {
    "top50",
    "topSub",
    "topWeb"
}


def extract_subdomain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]  # Removes 'www.'
    return domain if domain else None


def main():
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 2:
        print("Usage: python statsView.py <COMMAND>")
        return

    command = sys.argv[1]
    if command in commands:
        jsonExtract(command)
    else:
        print("Command not found, valid commands are [top50, topSub, topWeb]")


def jsonExtract(command):
    try:
        # Load the JSON file
        with open("crawlerStat.json", 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Process the command
        if command == "top50":
            word_freq = data[0]

            # Sort the dictionary by values
            sorted_words = sorted(word_freq.items(), key=lambda x: (-x[1], x[0]))

            # Extract the top 50 words
            top50 = sorted_words[:50]

            # Display the top 50 words and their frequencies
            print("Top 50 Words:")
            for word, freq in top50:
                print(f"{word}: {freq}")
        elif command == "topWeb":
            websites = data[1]
            topweb = max(websites.items(), key=lambda x: x[1])
            print(f"Top Website: {topweb[0]} "
                  f"\nWord Count:{topweb[1]}"
                f"\nWebsite Count: {len(websites)}")
        elif command == "topSub":
            subdomains = {}
            for url in data[1]:
                subdomain = extract_subdomain(url)
                if subdomain:
                    full_url = f"http://{subdomain}"  # Ensure all subdomains follow write up standard
                    subdomains[full_url] = subdomains.get(full_url, 0) + 1

            if subdomains:
                # Sort subdomains by frequency/ alphabetic
                sorted_subdomains = sorted(subdomains.items(), key=lambda x: (-x[1], x[0]))
                print("Top Subdomains:")
                for subdomain, freq in sorted_subdomains:
                    print(f"{subdomain}: {freq}")
                print(f"\nSubdomain Count: {len(sorted_subdomains)}")

            else:
                print("No subdomains found.")
    except FileNotFoundError:
        print(f"Error: JSON file  not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in .")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
