/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function securityQuestion () {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = utils.jwtFrom(req)
    const decodedToken = security.verify(token) && security.decode(token)

    if (decodedToken?.data == null) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const email = req.query.email
    const isAdmin = decodedToken.data.role === security.roles.admin

    const userWhere = isAdmin
      ? { email: email?.toString() }
      : { id: decodedToken.data.id, email: email?.toString() }

    SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: userWhere
      }]
    }).then((answer: SecurityAnswerModel | null) => {
      if (answer != null) {
        SecurityQuestionModel.findByPk(answer.SecurityQuestionId).then((question: SecurityQuestionModel | null) => {
          res.json({ question })
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        res.json({})
      }
    }).catch((error: unknown) => {
      next(error)
    })
  }
}