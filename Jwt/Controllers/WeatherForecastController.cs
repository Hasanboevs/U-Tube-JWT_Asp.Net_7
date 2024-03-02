using Jwt.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Jwt.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class WeatherForecastController : ControllerBase
	{
		private static readonly string[] Summaries = new[]
		{
			"Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
		};

		

		[HttpGet("Get")]
		public IActionResult Get()
		{
			return Ok(Summaries);
		}


		[HttpGet("GetUserRole")]
		[Authorize(Roles = StaticUserRole.User)]
		public IActionResult GetUserRole()
		{
			return Ok(Summaries);
		}

		[HttpGet("GetAdminRole")]
		[Authorize(Roles = StaticUserRole.Admin)]
		public IActionResult GetAdminRole()
		{
			return Ok(Summaries);
		}

		[HttpGet("GetOwnerRole")]
		[Authorize(Roles = StaticUserRole.Owner)]
		public IActionResult GetOwnerRole()
		{
			return Ok(Summaries);
		}
	}
}
