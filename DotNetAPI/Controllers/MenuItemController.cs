using DotNetAPI.Data;
using DotNetAPI.Models;
using DotNetAPI.Models.Dto;
using DotNetAPI.Services;
using DotNetAPI.Utility;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace DotNetAPI.Controllers
{
    [Route("api/MenuItem")]
    [ApiController]
    public class MenuItemController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly IBlobService _blobService;
        private ApiResponse _response;

        public MenuItemController(ApplicationDbContext db, IBlobService blobService)
        {
            _db = db;
            _blobService = blobService;
            _response = new ApiResponse();
        }

        [HttpGet]
        public async Task<IActionResult> GetMenuItems()
        {
            _response.Result = _db.MenuItems;
            _response.StatusCode = HttpStatusCode.OK;
            return Ok(_response);
        }

        [HttpGet("{id:int}", Name = "GetMenuItem")]
        public async Task<IActionResult> GetMenuItem(int id)
        {
            if(id ==0)
            {
                _response.StatusCode = HttpStatusCode.BadRequest;
                _response.IsSuccess = false;
                return BadRequest(_response); 
            }
            MenuItem menuItem = _db.MenuItems.FirstOrDefault(u => u.Id == id);
            if (menuItem == null)
            {
                _response.StatusCode = HttpStatusCode.NotFound;
                _response.IsSuccess = false;
                return NotFound(_response);
            }
            _response.Result = menuItem;
            _response.StatusCode = HttpStatusCode.OK;
            return Ok(_response);
        }

        [HttpPost]
        public async Task<ActionResult<ApiResponse>> CreateMenuItem([FromForm]MenuItemCreateDTO menuItemCreateDTO)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (menuItemCreateDTO.File == null || menuItemCreateDTO.File.Length == 0)
                    {
                        _response.StatusCode = HttpStatusCode.BadRequest;
                        _response.IsSuccess = false;
                        return BadRequest();
                    }
                    string fileName = $"{Guid.NewGuid()}{Path.GetExtension(menuItemCreateDTO.File.FileName)}";
                    MenuItem menuItemToCrete = new() // mapping to database
                    {
                        Name = menuItemCreateDTO.Name,
                        Price = menuItemCreateDTO.Price,
                        Category = menuItemCreateDTO.Category,
                        SpecialTag = menuItemCreateDTO.SpecialTag,
                        Description = menuItemCreateDTO.Description,
                        Image = await _blobService.UploadBlob(fileName,SD.SD_Storage_Container,menuItemCreateDTO.File)
                    };
                    _db.MenuItems.Add(menuItemToCrete);
                    _db.SaveChanges();
                    _response.Result = menuItemToCrete;
                    _response.StatusCode = HttpStatusCode.Created;
                    return CreatedAtRoute("GetMenuItem", new {id=menuItemToCrete.Id}, _response);
                }
                else
                {
                    _response.IsSuccess = false;
                }
            }
            catch (Exception ex)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
            }

            return _response;
        }

        [HttpPut("{id:int}")]
        public async Task<ActionResult<ApiResponse>> UpdateMenuItem(int id,[FromForm] MenuItemUpdateDTO menuItemUpdateDTO)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (menuItemUpdateDTO == null || id != menuItemUpdateDTO.Id)
                    {
                        _response.StatusCode = HttpStatusCode.BadRequest;
                        _response.IsSuccess = false;
                        return BadRequest();
                    }

                    //MenuItem menuItemFromDb = await _db.MenuItems.FirstOrDefaultAsync(u => u.Id == id);
                    MenuItem menuItemFromDb = await _db.MenuItems.FindAsync(id);
                    if (menuItemFromDb == null)
                    {
                        _response.StatusCode = HttpStatusCode.BadRequest;
                        _response.IsSuccess = false;
                        return BadRequest();
                    }

                    menuItemFromDb.Name = menuItemUpdateDTO.Name; // updating other details
                    menuItemFromDb.Price = menuItemUpdateDTO.Price;
                    menuItemFromDb.Category = menuItemUpdateDTO.Category;
                    menuItemFromDb.SpecialTag = menuItemUpdateDTO.SpecialTag;
                    menuItemFromDb.Description = menuItemUpdateDTO.Description;

                    if(menuItemUpdateDTO.File != null && menuItemUpdateDTO.File.Length > 0) // updating the image
                    {
                        string fileName = $"{Guid.NewGuid()}{Path.GetExtension(menuItemUpdateDTO.File.FileName)}";
                        // delete the existing image
                        await _blobService.DeleteBlob(menuItemFromDb.Image.Split('/').Last(), SD.SD_Storage_Container);

                        //updating
                        menuItemFromDb.Image = await _blobService.UploadBlob(fileName, SD.SD_Storage_Container, menuItemUpdateDTO.File);
                    }
                                        
                    _db.MenuItems.Update(menuItemFromDb);
                    _db.SaveChanges();
                    
                    _response.StatusCode = HttpStatusCode.NoContent;
                    return Ok(_response);
                }
                else
                {
                    _response.IsSuccess = false;
                }
            }
            catch (Exception ex)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
            }

            return _response;
        }



        [HttpDelete("{id:int}")]
        public async Task<ActionResult<ApiResponse>> DeleteMenuItem(int id)
        {
            try
            {
                
                if ( id == 0)
                {
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false;
                    return BadRequest();
                }

                //MenuItem menuItemFromDb = await _db.MenuItems.FirstOrDefaultAsync(u => u.Id == id);
                MenuItem menuItemFromDb = await _db.MenuItems.FindAsync(id);
                if (menuItemFromDb == null)
                {
                    _response.StatusCode = HttpStatusCode.BadRequest;
                    _response.IsSuccess = false;
                    return BadRequest();
                }

                await _blobService.DeleteBlob(menuItemFromDb.Image.Split('/').Last(), SD.SD_Storage_Container);
                int milliseconds = 2000;
                Thread.Sleep(milliseconds);

                _db.MenuItems.Remove(menuItemFromDb);
                _db.SaveChanges();

                _response.StatusCode = HttpStatusCode.NoContent;
                return Ok(_response);
               
            }
            catch (Exception ex)
            {
                _response.IsSuccess = false;
                _response.ErrorMessages = new List<string>() { ex.ToString() };
            }

            return _response;
        }
    }
}
