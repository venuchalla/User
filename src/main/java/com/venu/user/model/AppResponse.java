package com.venu.user.model;

public record AppResponse<T>(String message, T data) {
}
