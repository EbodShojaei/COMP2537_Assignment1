# COMP2537_Assignment1

A simple website using Node.js that connects to an encrypted MongoDB database to store the users with their names, emails and passwords.

	 Author: Ebod Shojaei
	 Version: 1.0


## Features:

- A home page links to signup and login, if not logged in; and links to members and signout, if logged in.
	>  **Includes**:
	> - use of parametrized query searches for protection against nosql-injection attacks.
	> - use of collation option for case insensitive querying of 'name' in user info to prevent writing duplicate names into the database.
	> - use of lowercase method for submitted emails to prevent writing duplicates into the database.

- A members page that displays 1 of 3 random images stored on the server.
	> The members page will redirect to the home page if no valid session is found.

- The signout buttons end the session.

- All secrets, encryption keys, database passwords are stored in a .env file.
	> The .env file is NOT in the git repo for obvious security reasons.

- Password is BCrypted in the MongoDB database.

- The site is hosted on Cyclic, a hosting service.

- A 404 page "catches" all invalid page hits and that sets the status code to 404.

- Session information is stored in an encrypted MongoDB session database. Sessions expire after 1 hour.

<br>

## Resources
- **[COMP2537_Demo_Code_1](https://github.com/greencodecomments/COMP2537_Demo_Code_1)** by greencodecomments
	- Used for setup
<br>

- **[ChatGPT-4](https://chat.openai.com/)** by OpenAI
	- Used for debugging