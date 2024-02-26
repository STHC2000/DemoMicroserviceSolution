using JWTAuthenticationManager.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthenticationManager
{
    public class JWTTokenHandler
    {
        public const string JWT_SECURITY_KEY = "yD7SfrVgJFKsXtrJd5VmHOJzD7uSE4vu";
        private const int JWT_TOKEN_VALIDITY_IN_MINUTES = 20;
        private List<UserAccount> _userAccountList;

        public JWTTokenHandler()
        {
            _userAccountList = new List<UserAccount>
            {
                new UserAccount {UserName="admin",Password="admin123",Role="Administrator"},
                new UserAccount {UserName="user01",Password="user01",Role="User"},
            };
        }

        public AuthenticationResponse? GenerateJwtToken(AuthenticationRequest authenticationRequest)
        {
            /*Check Username and password,if empty then return null*/
            if (string.IsNullOrWhiteSpace(authenticationRequest.UserName) ||
                string.IsNullOrWhiteSpace(authenticationRequest.Password))
            {
                return null;
            }

            /*Validation*/
            var userAccount = _userAccountList.
                                Where(x => x.UserName == authenticationRequest.UserName
                                && x.Password == authenticationRequest.Password).FirstOrDefault();

            if (userAccount == null) return null;

            //Get Timestamp
            var tokenExpireTimeStamp = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY_IN_MINUTES);
            //convert jwt key into bytes
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURITY_KEY);

            //create an object of claims
            var claimsIdentity = new ClaimsIdentity(new List<Claim> {
                new Claim(JwtRegisteredClaimNames.Name,authenticationRequest.UserName),
                new Claim("Role",userAccount.Role)
            });

            //create object based on token key and algorithm
            var newSigningCredentilas = new SigningCredentials(
                 new SymmetricSecurityKey(tokenKey),
                 SecurityAlgorithms.HmacSha256Signature);

            //create object which have claims subject,time of expiry and signing credentials
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpireTimeStamp,
                SigningCredentials = newSigningCredentilas
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            //create token
            var secutiryToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            //finally,we get token here 
            var token = jwtSecurityTokenHandler.WriteToken(secutiryToken);

            //Now,return Response
            return new AuthenticationResponse
            {
                UserName = userAccount.UserName,
                JwtToken = token,
                ExpiresIn = (int)tokenExpireTimeStamp.Subtract(DateTime.Now).TotalSeconds
            };


        }

    }
}
