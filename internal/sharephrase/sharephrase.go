package sharephrase

import (
	"bufio"
	"embed"
	"math/rand"
	"strconv"
	"strings"
)

//go:embed words.txt
var fs embed.FS

const NUM_WORDS = 7776

func GetRandomPhrase(numWords int, includeNums bool) (string, error) {
	allWords, err := getAllWords()
	if err != nil {
		return "", err
	}

	builder := &strings.Builder{}
	for range numWords {
		_, err = builder.WriteString(getRandomWord(allWords))
		if err != nil {
			return "", err
		}
	}

	if includeNums {
		_, err = builder.WriteString(strconv.Itoa(rand.Intn(1000)))
		if err != nil {
			return "", err
		}
	}

	return builder.String(), nil
}

func getRandomWord(words []string) string {
	word := words[rand.Int31n(int32(len(words)))]
	return strings.Title(strings.TrimSpace(word))
}

func getAllWords() ([]string, error) {
	file, err := fs.Open("words.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	s := bufio.NewScanner(file)

	words := make([]string, 0, NUM_WORDS)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) > 0 {
			words = append(words, line)
		}
	}

	return words, s.Err()
}
