package org.springjson.Service;

import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springjson.domain.User;

@RequestMapping("/api")
@Controller
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/signup")
    public String addnewproduct(Model model) {

        return "signup";
    }
    @GetMapping("/signin")
    public String login(Model model) {
        return "signin";
    }

    @PostMapping("/datasubmit")
    public String datasubmit(@Valid @ModelAttribute("user") User user, BindingResult Result) {
        if (Result.hasErrors()) {
            return "signup";
        }
        userService.saveuser(user);
        return "redirect:/api/alluser";
    }

    @GetMapping("/alluser")
    public String alluser(Model model) {
        model.addAttribute("alluser", userService.getUsers());
        return "alluser";
    }


}
