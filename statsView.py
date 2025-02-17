import json
import sys


commands = {
    "top50",
    "topSub",
    "topWeb"
}


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
                  f"\nWord Count:{topweb[1]}")
        elif command == "topSub":
            subdomain = data[2]
            topsub = max(subdomain.items(), key=lambda x: x[1])
            print(f"Top subdomain: {topsub[0]} "
                  f"\nFrequency: {topsub[1]}")
    except FileNotFoundError:
        print(f"Error: JSON file  not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in .")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
