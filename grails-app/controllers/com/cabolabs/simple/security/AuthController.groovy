package com.cabolabs.simple.security

import grails.transaction.Transactional

@Transactional(readOnly = true)
class AuthController {

   static defaultAction = "login"

   // send email with link
   //def mailService // TODO: email method should be implemented by client (IoC) or disabled
   def g = grailsApplication.mainContext.getBean('org.grails.plugins.web.taglib.ApplicationTagLib')

   def login(String username, String password)
   {
      if (request.post)
      {
         if (!username)
         {
            flash.message = message(code:"user.login.noUsername")
            return
         }

         def user = User.findByUsername(username)

         if (!user)
         {
            flash.message = message(code:"user.login.wrongUsername")
            return
         }

         if (!user.enabled)
         {
            flash.message = message(code:"user.login.userDisabled")
            return
         }

         if (!user.isPasswordValid(user.password, password))
         {
            flash.message = message(code:"user.login.wrongPassword")
            return
         }

         // login OK!
         session.user = user.plainData

         // shows dashboard depending on user role
         redirect controller: "dashboard" // TODO: default or config value by client
      }

      // render login
   }

   def logout()
   {
      session.user = null
      redirect action: "login"
   }

   // sends email because the user forgot his password
   @Transactional
   def resetPasswordRequest(String email)
   {
      if (request.post)
      {
         if (!email)
         {
            flash.message = message(code:"user.resetPasswordRequest.noEmail")
            return
         }

         def user = User.findByEmail(email)

         if (!user)
         {
            flash.message = message(code:"user.resetPasswordRequest.emailDoesntExists")
            return
         }

         // generates a password reset token, used in the email notification
         user.setPasswordToken()
         try
         {
            user.save(failOnError: true)
         }
         catch (Exception e)
         {
            println e.message
            flash.message = message(code:"user.resetPasswordRequest.cantRequestPasswordReset")
            return
         }



         // send password reset email
         // TODO: use async to send it so the user doesnt have to wait
         def url = g.createLink(controller:'auth', action:'reset', absolute:true, params:[token:user.passwordToken])

         /*
         mailService.sendMail {
            to user.email
            from "info@cabolabs.com"
            subject "Password reset was requested for your account"
            text 'Reset your password here '+ url
         }
         */

         session.user_id = user.id

         redirect action: 'resetRequestedFeedback'
         return
      }

      // render password reset view
   }

   // after successful resetPasswordRequest
   def resetRequestedFeedback()
   {
      [user: User.get(session.user_id)]
   }

   // access from email to reset the password from a password reset view
   @Transactional
   def resetPassword(String token, String newPassword, String confirmNewPassword)
   {
      if (!token)
      {
         flash.message = message(code:"user.resetPassword.noToken")
         redirect action:'login'
         return
      }

      def user = User.findByResetPasswordToken(token)

      if (!user)
      {
         flash.message = message(code:"user.resetPassword.invalidToken")
         redirect action: 'login'
         return
      }

      if (request.post)
      {
         // TODO: do pass reset
         // https://github.com/ppazos/cabolabs-ehrserver/blob/master/grails-app/controllers/com/cabolabs/security/UserController.groovy#L670
         if (!newPassword || !confirmNewPassword)
         {
            flash.message = message(code:"user.resetPassword.passwordConfirmationNeeded")
            return
         }

         def min_length = grailsApplication.config.getProperty('cabolabs.security.min_password_length', Integer)
         if (newPassword.size() < min_length)
         {
            flash.message = message(code:"user.resetPassword.passNotLongEnough", args:[min_length])
            return
         }

         if (newPassword != confirmNewPassword)
         {
            flash.message = message(code:"user.resetPassword.confirmDoesntMatch")
            return
         }

         user.password = newPassword
         user.enabled = true
         user.emptyPasswordToken()
         try
         {
            user.save(failOnError: true)
         }
         catch (Exception e)
         {
            println e.message
            flash.message = message(code:"user.resetPassword.errorResetingPassword")
            return
         }

         flash.message = message(code:"user.resetPassword.passwordResetOK")
         redirect action:'login'
         return
      }

      // render password reset view
   }
}
