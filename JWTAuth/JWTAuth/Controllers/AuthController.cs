using JWTAuth.Models;
using JWTAuth.Business.AuthService.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuth.Controllers
{
    [Route("[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // POST: auth/login
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginUser user)
        {
            if (String.IsNullOrEmpty(user.UserName))
            {
                return BadRequest(new { message = "Email vacio" });
            }
            else if (String.IsNullOrEmpty(user.Password))
            {
                return BadRequest(new { message = "Password vacio" });
            }

            User loggedInUser = await _authService.Login(user.UserName, user.Password);

            if (loggedInUser != null)
            {
                return Ok(loggedInUser);
            }

            return BadRequest(new { message = "User login error" });
        }

        // POST: auth/register
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser user)
        {
            if (String.IsNullOrEmpty(user.Name))
            {
                return BadRequest(new { message = "Name vacio" });
            }
            else if (String.IsNullOrEmpty(user.UserName))
            {
                return BadRequest(new { message = "User vacio" });
            }
            else if (String.IsNullOrEmpty(user.Password))
            {
                return BadRequest(new { message = "Password vacio" });
            }

            User userToRegister = new(user.UserName, user.Name, user.Password, user.Role);

            User registeredUser = await _authService.Register(userToRegister);

            User loggedInUser = await _authService.Login(registeredUser.UserName, user.Password);

            if (loggedInUser != null)
            {
                return Ok(loggedInUser);
            }

            return BadRequest(new { message = "error al registrar" });
        }

        // GET: auth/test
        [Authorize(Roles = "ADMIN")]
        [HttpGet]
        public IActionResult Test()
        {
            string token = Request.Headers["Authorization"];

            if (token.StartsWith("Bearer"))
            {
                token = token.Substring("Bearer ".Length).Trim();
            }
            var handler = new JwtSecurityTokenHandler();

            JwtSecurityToken jwt = handler.ReadJwtToken(token);

            var claims = new Dictionary<string, string>();

            foreach(var claim in jwt.Claims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            return Ok(claims);
        }
    }
}
