using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pronia.DAL;
using Pronia.Extensions;
using Pronia.Models;
using Pronia.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Areas.ProniaAdmin.Controllers
{
    [Area("ProniaAdmin")]
    public class SliderController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public SliderController(AppDbContext context,IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        public async Task<IActionResult> Index()
        {
            List<Slider> sliders = await _context.Sliders.ToListAsync();
            return View(sliders);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Slider slider)
        {
            if (!ModelState.IsValid) return View();
            if (slider.Photo != null)
            {
                
                if (slider.Photo.IsOkay(1))
                {
                    ModelState.AddModelError("Photo", "Please, choose image file which size under 1 Mb");
                    return View();
                }
               
                slider.Image = await slider.Photo.FileCreate(_env.WebRootPath, @"assets\images\website-images");
                await _context.Sliders.AddAsync(slider);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            else
            {
                ModelState.AddModelError("Photo", "Please, choose file");
                return View();
            }
           
        }
        public async Task<IActionResult> Detail(int id)
        {
            Slider slider = await _context.Sliders.FirstOrDefaultAsync(s=>s.Id==id);
            if (slider == null) return NotFound();
            
            return View(slider);
        }
        public async Task<IActionResult> Edit(int id)
        {
            Slider slider =  await _context.Sliders.FirstOrDefaultAsync(s=>s.Id==id);
            if (slider==null)
            {
                return NotFound();
            }
            return View(slider);
        }
        [HttpPost]
        public async Task<IActionResult> Edit(int id, Slider slider)
        {
            if (!ModelState.IsValid)
            {
                return View(slider);
            }
            Slider existedSlider = await _context.Sliders.FirstOrDefaultAsync(s => s.Id == id);
            if (slider.Photo !=null)
            {
                if (!slider.Photo.IsOkay(1))
                {
                    string path = _env.WebRootPath + @"\assets\images\website-images\" + existedSlider.Image;
                    if (System.IO.File.Exists(path))
                    {
                        System.IO.File.Delete(path);
                    }
                    existedSlider.Image = await slider.Photo.FileCreate(_env.WebRootPath, @"assets\images\website-images");

                }
                else
                {
                    ModelState.AddModelError("Photo", "Selected image is not valid!");
                    return View(slider);
                }
            }
            existedSlider.Title = slider.Title;
            existedSlider.SubTitle = slider.SubTitle;
            existedSlider.Discount = slider.Discount;
            existedSlider.DiscoverUrl = slider.DiscoverUrl;
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));

        }
        public async Task<IActionResult> Delete(int id)
        {
            Slider slider = await _context.Sliders.FirstOrDefaultAsync(s=>s.Id==id);
            if (slider == null) return NotFound();
           
            return View(slider);
        }
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        [ActionName("Delete")]
        public async Task<IActionResult> DeleteSlider(int id)
        {
            Slider slider = await _context.Sliders.FirstOrDefaultAsync(s => s.Id == id);
            if (slider == null) return NotFound();
            _context.Sliders.Remove(slider);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
    }
}
