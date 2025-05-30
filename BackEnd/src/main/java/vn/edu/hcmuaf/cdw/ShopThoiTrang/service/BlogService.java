package vn.edu.hcmuaf.cdw.ShopThoiTrang.service;

import org.springframework.data.domain.Page;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.Blog;

import java.util.List;

public interface BlogService {
    Page<Blog> getAllBlogs(String filter, int page, int perPage, String sortBy, String order);

    List<Blog> getBlogsStatusTrue();

    Blog getBlogById(Long id);

    Blog saveBlog(Blog blog);
    Blog updateBlog(Long id, Blog blog);


}
