using Microsoft.AspNetCore.Mvc;

namespace ZeelandWalksApi.Controllers
{
    //https://localhost:portnumber/api/students
    [Route("api/controller")]
    [ApiController]
    public class StudentsController : ControllerBase
    {
        //GET: https://localhost:portnumber/api/students
        [HttpGet]
        public IActionResult GetAllStudents()
        {
            // Playing from database
            string[] studentNames = new string[] { "Reidar", "Alf", "Tobias", "Aldor" };
            return( Ok(studentNames));
        }
    }
}
