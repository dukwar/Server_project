const {Router} = require('express')
const User = require('../models/User')
const {check, validationResult} = require('express-validator') // валидация тела запроса
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const router = Router()

// /api/auth/register
router.post(
    '/register', [
        check('email', 'Некорректный email').isEmail(), // валидируем email, isEmail - встроенный метод в express-validator
        check('password', 'Минимальная длина пароля 6 символов').isLength({min: 6})
    ],
    async (req, res) => {
        try {

            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors,
                    message: 'Некорректные данные при регистрации '
                })

            }

            const {email, password} = req.body // тело запроса, получаем поля из объекта request

            const candidate = await User.findOne({email}) // поиск email в схеме юзера
            if (candidate) {
                return res.status(400).json({message: 'Такой пользователь существует'})
            }

            const hashedPassword = await bcrypt.hash(password, 12) // хешируем пароль чтобы не взломали
            const user = new User({email, password: hashedPassword}) // созадем нового пользователя

            await user.save() // ждем пока пользователь сохранится

            res.status(201).json({message: 'Пользователь создан'}) // 201 статус создается и после манипуляций создан


        } catch (e) {
            res.status(500).json({message: 'Что то пошло не так, попробуйте снова'})
        }

    })




router.post(
    '/login', [
        check('email', 'Введите корректный email').normalizeEmail().isEmail(), // валидируем email, isEmail - встроенный метод в express-validator
        check('password', 'Введите пароль').exists()
    ],
    async (req, res) => {
        try {

            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors,
                    message: 'Некорректные данные при входу в систему'
                })
            }


            const {email, password} = req.body

            const user = await User.findOne({email})

            if (!user) {
                return  res.status(400).json({message: 'Пользователь не найден'})
            }
            
            const isMatch = await bcrypt.compare(password, user.password) // обращаемся к бикрипту который позволяет проверять совпадают ли пароли

            if (!isMatch) {
                return res.status(400).json({message: 'Неверный пароль попробуйте снова'})
            }


            const token = jwt.sign( // делаем авторизацию через jwt token
                {userId: user.id}, // данные которые будут зашифрованы в токене, id пользователя, можно добавить и name, email
                config.get('jwtSecret'), // секретный ключ
                {expiresIn: '1h'} // жизнь токена
            )

            res.json({token, userId: user.id}) // логин завершен



        } catch (e) {
            res.status(500).json({message: 'Что то пошло не так, попробуйте снова'})
        }

    })


module.exports = router