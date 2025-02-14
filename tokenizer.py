# Modified Nguyen code :D
import re


def tokenize(webtext: str) -> list:
    if not webtext:
        return []
    else:
        pattern = r"[a-zA-Z0-9]+"
    # UPDATE LATER TO READ BY BYTE INSTEAD OF ALL AT ONCE
        return re.findall(pattern, webtext.lower())


# Copied directly from ranks.nl/stopwords
# didn't include words like "i've" since our tokenizer doesn't include words with apostrophes
# ALSO REMOVED SUFFIX LIKE "s", "ve", "d", "ll", "t"
stop_words = [
    "s", "ve", "d", "ll", "t",
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "as", "at",
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "cannot", "could",
    "did", "do", "does", "doing", "down", "during", "each", "few", "for",
    "from", "further", "had", "has", "have", "having", "he",
    "her", "here", "hers", "herself", "him", "himself", "his", "how", "i",
    "if", "in", "into", "is", "it", "its", "itself", "me", "more", "most",
    "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours",
    "ourselves", "out", "over", "own", "same", "she", "should",
    "so", "some", "such", "than", "that", "the", "their", "theirs", "them", "themselves", "then", "there",
    "these", "they", "this", "those", "through", "to", "too",
    "under", "until", "up", "very", "was", "we", "were", "what",
    "when", "where", "which", "while", "who", "whom", "why", "with",
    "would", "you", "your", "yours", "yourself", "yourselves"]


def computeWordFrequencies(token_list: list) -> dict:
    token_dict = {}

    for token in sorted(token_list):
        if token in stop_words:
            continue
        elif token in token_dict:
            token_dict[token] += 1
        else:
            token_dict[token] = 1

    return dict(sorted(token_dict.items(), key=lambda item: item[1], reverse = True))


# JUNKED FOR NOW, can use if we run into errors with tokenizing big websites
# def stream_tokens(text):
#     for word in re.finditer(r'\w+', text):
#         yield word.group()


# def main():
#     if len(sys.argv) != 2:
#         sys.exit()
#
#     token_list = tokenize(sys.argv[1])
#     token_dict = computeWordFrequencies(token_list)
#     # printTokens(token_dict)


# if __name__ == "__main__":
#     main()
