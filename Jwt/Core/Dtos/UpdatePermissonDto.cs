using System.ComponentModel.DataAnnotations;

namespace Jwt.Core.Dtos
{
	public class UpdatePermissonDto
	{
		[Required(ErrorMessage = "Username is required")]
		public string UserName { get; set; }
	}
}
