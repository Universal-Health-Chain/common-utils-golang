package envUtils

import (
	"fmt"

	"github.com/joho/godotenv"
)

// Both main.go and the test functions shall this function
func LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		err = godotenv.Load("../.env")
		if err != nil {
			err = godotenv.Load("../../.env")
			if err != nil {
				err = godotenv.Load("../../../.env")
				if err != nil {
					err = godotenv.Load("../../../../.env")
					if err != nil {
						err = godotenv.Load("../../../../../.env")
						if err != nil {
							err = godotenv.Load("../../../../../../.env")
							if err != nil {
								err = godotenv.Load("../../../../../../../.env")
								if err != nil {
									err = godotenv.Load("../../../../../../../../.env")
									if err != nil {
										err = godotenv.Load("../../../../../../../../...env")
										if err != nil {
											fmt.Printf("utils: cannot get environment data: %v\n", err)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
