/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    const authenticatedAuthor = user?.data?.email

    if (authenticatedAuthor == null) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    challengeUtils.solveIf(
      challenges.forgedReviewChallenge,
      () => authenticatedAuthor !== req.body.author
    )

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: authenticatedAuthor,
        likesCount: 0,
        likedBy: []
      })
      return res.status(201).json({ status: 'success' })
    } catch (err: unknown) {
      return res.status(500).json(utils.getErrorMessage(err))
    }
  }
}