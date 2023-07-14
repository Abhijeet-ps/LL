import jwt, { TokenExpiredError } from "jsonwebtoken";
import { NextFunction, Request, Response } from "express";
import User from "../models/user-model";

export interface AuthRequest extends Request {
  user: string;
}

export const authenticationMiddleware = async (
  request: AuthRequest,
  response: Response,
  next: NextFunction
) => {
  try {
    const { authorization } = request.headers;
    if (!authorization) {
      return response.status(401).json({
        error: "Authorization is required",
      });
    }
    const token = authorization;
    let decodedToken: any;
    try {
      decodedToken = jwt.verify(token, "express");
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        try {
          const { exp, ...payloadWithoutExp } = jwt.decode(token) as Record<string, any>; // Extract payload from the expired token
          const newToken = jwt.sign(payloadWithoutExp, "express", {
            expiresIn: "30d", // Set the expiration for the new token
          });
          decodedToken = jwt.verify(newToken, "express"); // Verify the new token
          response.setHeader("Authorization", newToken); // Update the response headers with the new token
        } catch (err) {
          console.log("Error generating new token:", err);
          return response.status(401).json({
            error: "Invalid token",
          });
        }
      } else {
        throw error;
      }
    }

    const { _id } = decodedToken;
    const existingUser = await User.findOne({ _id });

    if (existingUser) {
      request.user = existingUser.id;
    }
    next();
  } catch (error) {
    console.log("error in authenticationMiddleware", error);
    throw error;
  }
};










// import jwt from "jsonwebtoken"
// import { NextFunction, Request, Response } from "express"
// import User from "../models/user-model"

// export interface AuthRequest extends Request {
//   user: string
// }

// export const authenticationMiddleware = async (
//   request: AuthRequest,
//   response: Response,
//   next: NextFunction
// ) => {
//   try {
//     const { authorization } = request.headers
//     if (!authorization) {
//       return response.status(401).json({
//         error: "Authorization is required",
//       })
//     }
//     const token = authorization
//     const { _id } = jwt.verify(token, "express")
//     const existingUser = await User.findOne({ _id })

//     if (existingUser) {
//       request.user = existingUser.id
//     }
//     next()
//   } catch (error) {
//     console.log("error in authenticationMiddleware", error)
//     throw error
//   }
// }
