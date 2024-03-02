﻿using Jwt.Core.Dtos;
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


	}
}
