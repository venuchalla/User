package com.venu.user.controller;

import com.venu.user.model.Greeting;
import com.venu.user.model.UserPage;
import com.venu.user.service.UserServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

import java.util.concurrent.atomic.AtomicLong;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping(path = "/pagination")
public class UserPaginationController {
    Logger logger = LoggerFactory.getLogger(UserPaginationController.class);
    String inputStringTem = "Hello %s,welcome to Pagination Controller";
    public final AtomicLong counter = new AtomicLong();
    @Autowired
    UserServiceImpl userServiceImpl;

    @RequestMapping(path = "", method = RequestMethod.GET, produces = {MediaType.APPLICATION_JSON_VALUE})
    Greeting ping(@RequestParam(value = "name", defaultValue = "Consumer") String s) {
        return new Greeting(counter.incrementAndGet(), String.format(inputStringTem, s));

    }

    @GetMapping(path = "/users", produces = {MediaType.APPLICATION_JSON_VALUE})
    ResponseEntity<UserPage> getusers(@RequestParam(value = "page", defaultValue = "0") int pageIndex, @RequestParam(value = "size", defaultValue = "3") int recordsPerPage) {
        logger.info("we are in getusers method page index {} size {}",pageIndex,recordsPerPage);
        Pageable pageable = PageRequest.of(pageIndex, recordsPerPage);
        return new ResponseEntity<>(userServiceImpl.getUserWithPageble(pageable), HttpStatus.CREATED);


    }

}
