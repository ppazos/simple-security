package com.cabolabs.simple.security

// TODO: move to service
import org.mindrot.jbcrypt.BCrypt

class User {

   String id
   String username

   // FIXME: this is just for testing initial password assignment, users with this UUID
   // will be inactive until they reset their passwrods, that will be hashed, ciphered
   // and with salt.
   // https://www.codeproject.com/Articles/704865/Salted-Password-Hashing-Doing-it-Right
   String password = java.util.UUID.randomUUID() as String

   Date dateCreated
   String phone // business contact phone
   String position // role in organization / job title: CTO, CEO, CIO, ...
   String role // TODO: mapping because is reserved work on dbms
   boolean enabled = false
   String email

   // This is set when the user is created from plan select,
   // inactive and without password.
   // The system sends an email to the new user with alink to
   // the reset password action, including this token in the link.
   String resetPasswordToken
   Date resetPasswordTokenSet // for expiration

   static constraints = {
      username unique: true
      email unique: true
      phone nullable: true
      position nullable: true
      role inList:['admin', 'publisher', 'subscriber'] // TODO: enum

      resetPasswordToken nullable: true
      resetPasswordTokenSet nullable: true
   }
   static mapping = {
      table 'users'
      id generator:'uuid2'
      password column: '`password`'
      position column: 'role_in_organization'
   }

   static transients = ['passwordToken', 'plainData']

   def beforeInsert()
   {
      println "User.beforeInser"
      if (this.password)
      {
         this.password = encodePassword(this.password)

         if (this.enabled) this.resetPasswordToken = null
      }
   }

   def beforeUpdate()
   {
      println "User.beforeUpdate"
      if (hasChanged('password')) // isDirty doesnt work with Grails 3 https://github.com/grails/grails-core/issues/10609
      {
         println "pass dirty"
         this.password = encodePassword(this.password)
      }
   }

   // used to put minimum user info on session.user after successful login
   def getPlainData()
   {
      [username: this.username, email: this.email, role: this.role, position: this.position]
   }

   // TODO: move to a service
   // https://docs.spring.io/spring-security/site/docs/2.0.7.RELEASE/apidocs/org/springframework/security/providers/encoding/PasswordEncoder.html
   private String encodePassword(String rawPass)
   {
      return BCrypt.hashpw(rawPass, BCrypt.gensalt())
   }

   private boolean isPasswordValid(String encPass, String rawPass)
   {
      return BCrypt.checkpw(rawPass, encPass)
   }

   def setPasswordToken()
   {
      this.resetPasswordToken = java.util.UUID.randomUUID() as String
      this.resetPasswordTokenSet = new Date()
   }

   def getPasswordToken()
   {
      return this.resetPasswordToken
   }

   def emptyPasswordToken()
   {
      this.resetPasswordToken = null
      this.resetPasswordTokenSet = null
   }

   // Should be executed from a job
   def checkExpirationPasswordToken()
   {
      def now = new Date()
      def token_valid_days = 5 // TODO: config

      if (now - this.resetPasswordTokenSet > token_valid_days)
      {
         emptyPasswordToken() // invalidates token
      }
   }
}
