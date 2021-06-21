const bcryptjs = require('bcryptjs');
const User = require('../models/user');
const jwt = require('jsonwebtoken');

function createToken(user, SECRET_KEY, expiresIn) {
	const { id, name, email, username } = user;
	const payload = {
		id,
		name,
		email,
		username,
	};
	return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

async function register(input) {
	const newUser = input;
	newUser.email = newUser.email.toLowerCase();
	newUser.username = newUser.username.toLowerCase();
	const { username, email, password } = newUser;

	// Verificamos si el email esta en uso
	const foundEmail = await User.findOne({ email });
	if (foundEmail) throw new Error('Email ya esta en uso');

	// Verificamos si el email esta en uso
	const foundUsername = await User.findOne({ username });
	if (foundUsername) throw new Error('Nombre de usuario ya esta en uso');

	// Encriptar

	const salt = await bcryptjs.genSaltSync(10);
	newUser.password = await bcryptjs.hash(password, salt);

	try {
		const user = new User(newUser);
		user.save();
		console.log(user, '======= try ======');
		return user;
	} catch (error) {
		console.log(error);
		console.log('Error Catch');
		return error;
	}
}

async function login(input) {
	const { email, password } = input;

	const userFound = await User.findOne({ email: email.toLowerCase() });
	if (!userFound) throw new Error('Email o constrasenha invalida');

	const passwordSucess = await bcryptjs.compare(password, userFound.password);
	if (!passwordSucess) throw new Error('Email o constrasenha invalida');

	return {
		token: createToken(userFound, process.env.SECRET_KEY, '24h'),
	};
}

module.exports = {
	register,
	login,
};
