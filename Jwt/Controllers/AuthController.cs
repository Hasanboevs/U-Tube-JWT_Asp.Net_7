using Jwt.Core.Dtos;
using Jwt.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Jwt.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly UserManager<IdentityUser> _usermanager;
		private readonly RoleManager<IdentityRole> _rolemanager;
		private readonly IConfiguration _configuration;

		public AuthController(UserManager<IdentityUser> manager, RoleManager<IdentityRole> rolemanager, IConfiguration configuration)
		{
			_usermanager = manager;
			_rolemanager = rolemanager;
			_configuration = configuration;
		}

		// Seeding Roles, Creating Roles
		[HttpPost("seed-roles")]
		public async Task<IActionResult> SeedRoles()
		{
			bool isOwnerRoleExists = await _rolemanager.RoleExistsAsync(StaticUserRole.Owner);
			bool isAdminRoleExists = await _rolemanager.RoleExistsAsync(StaticUserRole.Admin);
			bool isUserRoleExists = await _rolemanager.RoleExistsAsync(StaticUserRole.User);

			if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
				return Ok("Roles are already done");

			await _rolemanager.CreateAsync(new IdentityRole(StaticUserRole.User));
			await _rolemanager.CreateAsync(new IdentityRole(StaticUserRole.Admin));
			await _rolemanager.CreateAsync(new IdentityRole(StaticUserRole.Owner));

			return Ok("Seeding Roles has been successfully done.");

		}


		// Registering as a user
		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] RegisterDto user)
		{
			var isUserExists = await _usermanager.FindByNameAsync(user.UserName);

			if (isUserExists != null)
				return BadRequest("Username already exists");

			IdentityUser user1 = new IdentityUser()
			{
				Email = user.Email,
				UserName = user.UserName,
				SecurityStamp = Guid.NewGuid().ToString(),
			};

			var result = await _usermanager.CreateAsync(user1, user.Password);

			if(!result.Succeeded)
			{
				var errorString = "Registeration has failed as: ";
                foreach (var error in result.Errors)
                {
					errorString += " # " + error.Description;
                }

				return BadRequest(errorString);
            }

			await _usermanager.AddToRoleAsync(user1, StaticUserRole.User);

			return Ok("Registeration has been successfully done");
		}
		
		// User Part
		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginDto user)
		{
			var name = await _usermanager.FindByNameAsync(user.UserName);
			var password = await _usermanager.CheckPasswordAsync(name, user.Password);

			if (name == null && !password)
				return Unauthorized("Invalid Credentials");

			var userRoles = await _usermanager.GetRolesAsync(name);

			var AuthClaims = new List<Claim>
			{
				new Claim(ClaimTypes.Name, name.UserName),
				new Claim(ClaimTypes.NameIdentifier, name.Id),
				new Claim("JWTID", Guid.NewGuid().ToString())
			};

            foreach (var role in userRoles)
            {
				AuthClaims.Add(new Claim(ClaimTypes.Role, role));
            }

			var token = GenerateNewJsonWebToken(AuthClaims);

			return Ok(token);
		}

		// Token Generator
		private string GenerateNewJsonWebToken(List<Claim> claims)
		{
			var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

			var tokenObject = new JwtSecurityToken(
				issuer: _configuration["JWT:ValidIssuer"],
				audience: _configuration["JWT:ValidAudience"],
				expires: DateTime.Now.AddHours(1),
				claims: claims,
				signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
			);
			string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

			return token;
		}

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenResponseDto refreshTokenDto)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var handler = new JwtSecurityTokenHandler();

            try
            {
                var principal = handler.ValidateToken(refreshTokenDto.RefreshToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = authSecret,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false 
                }, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    var username = principal.Identity.Name; 


                    var newAccessToken = GenerateNewAccessToken(principal.Claims);
                    return Ok(new { accessToken = newAccessToken });
                }
            }
            catch (Exception ex)
            {
                return BadRequest("Invalid refresh token");
            }

            return BadRequest("Invalid refresh token");
        }

        private string GenerateNewAccessToken(IEnumerable<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenObject);
        }



        // Make user Admin

        [HttpPost("make-admin")]
		public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissonDto perm)
		{
			var user = await _usermanager.FindByNameAsync(perm.UserName);

			if (user == null)
				return BadRequest("Invalid Username!");

			await _usermanager.AddToRoleAsync(user, StaticUserRole.Admin);
			return Ok("User is now an Admin");
		}


		// Make user Owner

		[HttpPost("make-owner")]
		public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissonDto perm)
		{
			var user = await _usermanager.FindByNameAsync(perm.UserName);

			if (user == null)
				return BadRequest("Invalid Username!");

			await _usermanager.AddToRoleAsync(user, StaticUserRole.Owner);
			return Ok("User is now an Owner");
		}




	}
}
