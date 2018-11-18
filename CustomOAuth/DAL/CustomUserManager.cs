using CustomOAuth.Api.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace CustomOAuth.Api.DAL
{
    public class CustomUserManager
    {
        public Tuple<bool, User> Login(string username, string password)
        {
            User user = new User();
            bool result =false;
            try
            {
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    user.Username = username;
                    user.Id = 1;
                    user.Roles = new List<string>
                    {
                         "Admin",
                        "User"
                    };
                    result = true;
                }
            }
            catch (Exception)
            {

                throw;
            }

            return new Tuple<bool, User>(result, user);

        }
    }
}