# Security Notes

- 2026-09-18: Anonymous GET `http://localhost:5000/recipes` returned all recipes, including the secret recipe (`is_public: false`, "Secret family hot sauce").
- 2026-09-18: Anonymous PATCH `http://localhost:5000/recipes/3` returned 200 OK and changed the title of the secret recipe to "Totally stolen hot sauce".
- 2026-09-18: Anonymous DELETE `http://localhost:5000/recipes/3` returned 204 NO CONTENT and the recipe no longer appears in `GET /recipes`.
