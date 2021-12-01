/* eslint-disable no-undef */
const request = require('supertest');
const bcrypt = require('bcrypt');
const app = require('../index');
const User = require('../database/models/users');
const mongoose = require('../database/dbConection');
const UserService = require('../database/services/users');
const RecipeService = require('../database/services/recipes');

jest.setTimeout(10000);
let id;
let token;
describe('test the recipes API', () => {
  beforeAll(async () => {
    // create a test user
    const password = bcrypt.hashSync('okay', 10);
    await User.create({
      username: 'admin',
      password,
    });
  });
  afterAll(async () => {
    await User.deleteMany();
    await mongoose.disconnect();
  });

  describe('POST/login', () => {
    it('authenticates user and sign him in', async () => {
      const user = {
        username: 'admin',
        password: 'okay',
      };
      const res = await request(app)
        .post('/login')
        .send(user);

      token = res.body.accessToken;
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual(
        expect.objectContaining({
          accessToken: token,
          success: true,
          data: expect.objectContaining({
            id: res.body.data.id,
            username: res.body.data.username,
          }),
        }),
      );
    });

    it('does not authenticate user, if password field is empty', async () => {
      const user = {
        username: 'admin',
      };
      const res = await request(app)
        .post('/login')
        .send(user);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'username or password can not be empty',
        }),
      );
    });

    it('does not authenticate user, if username field is empty', async () => {
      const user = {
        username: 'okay',
      };
      const res = await request(app)
        .post('/login')
        .send(user);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'username or password can not be empty',
        }),
      );
    });

    it('does not authenticate user that does not exist', async () => {
      const user = {
        username: 'orzu',
        password: 'okay',
      };
      const res = await request(app)
        .post('/login')
        .send(user);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Incorrect username or password',
        }),
      );
    });

    it('does not authenticate user with incorrect password', async () => {
      const user = {
        username: 'admin',
        password: 'okay1',
      };
      const res = await request(app)
        .post('/login')
        .send(user);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Incorrect username or password',
        }),
      );
    });

    it('does not sign him in, internal server error', async () => {
      const user = {
        username: 'admin',
        password: 'okay',
      };
      jest.spyOn(UserService, 'findByUsername')
        .mockRejectedValueOnce(new Error());
      const res = await request(app)
        .post('/login')
        .send(user);
      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'login failed.',
        }),
      );
    });
  });

  describe('POST/recipies', () => {
    it('should save new recipe to db', async () => {
      const recipe = {
        name: 'plov',
        difficulty: 2,
        vegetarian: false,
      };
      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(201);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: true,
          data: expect.any(Object),
        }),
      );
      // eslint-disable-next-line no-underscore-dangle
      id = res.body.data._id;
    });

    it('does not save recipe to db if it contains invalid vegetarian value', async () => {
      const recipe = {
        name: 'somsa',
        difficulty: 4,
        vegetarian: 'true',
      };
      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'vegetarian field should be boolean',
        }),
      );
    });

    it('does not save recipes to db without name field', async () => {
      const recipe = {
        difficulty: 3,
        vegetarian: true,
      };
      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'name field can not be empty',
        }),
      );
    });

    it('does not save recipes to db with invalid difficulty field', async () => {
      const recipe = {
        name: 'manti',
        difficulty: '5',
        vegetarian: false,
      };

      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'difficulty field should be a number',
        }),
      );
    });

    it('does not save recipes to db with invalid token', async () => {
      const recipe = {
        name: 'Lagman',
        difficulty: 5,
        vegetarian: true,
      };
      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', 'Bearer dfjhsjfhjsdfhrjsd4787eyw7y');

      expect(res.statusCode).toBe(403);
      expect(res.body).toEqual(
        expect.objectContaining({
          message: 'Unauthorized',
        }),
      );
    });

    it('does not save recipes to db, internal server error', async () => {
      jest.spyOn(RecipeService, 'saveRecipes')
        .mockRejectedValueOnce(new Error());
      const recipe = {
        name: 'plov',
        difficulty: 3,
        vegetarian: false,
      };
      const res = await request(app)
        .post('/recipes')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);
      expect(res.statusCode).toEqual(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Failed to save recipes!',
        }),
      );
    });
  });

  describe('GET/recipes', () => {
    it('retrives all the recipes inside db', async () => {
      const res = await request(app)
        .get('/recipes');

      expect(res.statusCode).toEqual(200);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: true,
          data: expect.any(Object),
        }),
      );
    });

    it('does not retrive all recipes, internal server error', async () => {
      jest.spyOn(RecipeService, 'allRecipes')
        .mockRejectedValueOnce(new Error());
      const res = await request(app)
        .get('/recipes');

      expect(res.statusCode).toBe(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Some error occurred while retrieving recipes.',
        }),
      );
    });
  });

  describe('GET/recipes/:id', () => {
    it('retrives a specified recipe', async () => {
      const res = await request(app)
        .get(`/recipes/${id}`);

      expect(res.statusCode).toEqual(200);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: true,
          data: expect.any(Object),
        }),
      );
    });

    it('does not retrive any recipe with invalid id', async () => {
      const res = await request(app)
        .get('/recipes/1q2w3e4r5t6y');

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Recipe with id 1q2w3e4r5t6y does not exist',
        }),
      );
    });

    it('does not retrieve recipe, internal server error', async () => {
      jest.spyOn(RecipeService, 'fetchById')
        .mockRejectedValueOnce(new Error());
      const res = await request(app)
        .get(`/recipes/${id}`);
      expect(res.statusCode).toEqual(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Some error occurred while retrieving recipe details.',
        }),
      );
    });
  });

  describe('PATCH/recipes/:id', () => {
    it('updates recipe record in db', async () => {
      const recipe = {
        name: 'plov',
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(200);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: true,
          data: expect.any(Object),
        }),
      );
    });

    it('does not update recipe in db with invalid difficulty field value', async () => {
      const recipe = {
        name: 'Manti',
        difficulty: '8',
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'difficulty field should be a number',
        }),
      );
    });

    it('does not update recipe in db with invalid vegetarian field value', async () => {
      const recipe = {
        name: 'Manti',
        vegetarian: 'false',
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'vegetarian field should be boolean',
        }),
      );
    });

    it('does not update recipe in db with invalid id', async () => {
      const recipe = {
        name: 'Manti',
        vegetarian: false,
      };
      const res = await request(app)
        .patch('/recipes/0o9i8u7y6t5r')
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'Recipe with id 0o9i8u7y6t5r does not exist',
        }),
      );
    });

    it('does not update recipe in db with invalid token', async () => {
      const recipe = {
        name: 'Manti',
        vegetarian: false,
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', 'Bearer sfhksdfhj4e7wr837');

      expect(res.statusCode).toEqual(403);
      expect(res.body).toEqual(
        expect.objectContaining({
          message: 'Unauthorized',
        }),
      );
    });

    it('does not update recipe in db if no changes made to it', async () => {
      const recipe = {
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'field should not be empty',
        }),
      );
    });

    it('does not update recipe with negative difficulty', async () => {
      const recipe = {
        difficulty: -9,
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'difficulty field should be a number',
        }),
      );
    });

    it('does not update recipe with difficulty over value 3', async () => {
      const recipe = {
        difficulty: 4,
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(400);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'difficulty field should be a number',
        }),
      );
    });

    it('does not update recipe in db, internal server error', async () => {
      jest.spyOn(RecipeService, 'fetchByIdAndUpdate')
        .mockRejectedValueOnce(new Error());
      const recipe = {
        name: 'H',
      };
      const res = await request(app)
        .patch(`/recipes/${id}`)
        .send(recipe)
        .set('Authorization', `Bearer ${token}`);
      expect(res.statusCode).toEqual(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'An error occured while updating recipe',
        }),
      );
    });
  });

  describe('DELETE/recipes/:id', () => {
    it('deletes the specific recipe', async () => {
      const res = await request(app)
        .delete(`/recipes/${id}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(200);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: true,
          message: 'Recipe successfully deleted',
        }),
      );
    });

    it('fails to delete specified recipe with invalid token', async () => {
      const res = await request(app)
        .delete(`/recipes/${id}`)
        .set('Authorization', 'Bearer sfhksdfhj4e7wr837');

      expect(res.statusCode).toEqual(403);
      expect(res.body).toEqual(
        expect.objectContaining({
          message: 'Unauthorized',
        }),
      );
    });

    it('fails to delete specified recipe, internal server error', async () => {
      jest.spyOn(RecipeService, 'fetchByIdAndDelete')
        .mockRejectedValueOnce(new Error());
      const res = await request(app)
        .delete(`/recipes/${id}`)
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toEqual(500);
      expect(res.body).toEqual(
        expect.objectContaining({
          success: false,
          message: 'An error occured while deleting recipe',
        }),
      );
    });
  });
});
