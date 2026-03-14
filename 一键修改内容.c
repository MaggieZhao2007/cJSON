#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

// 定义值类型枚举（与cJSON类型对应）
typedef enum {
    VAL_STRING,
    VAL_NUMBER,
    VAL_BOOL,
    VAL_NULL
} cJSON_ValueType;

/**
 * @brief 快速修改cJSON节点的值
 * @param node 要修改的节点（非空）
 * @param type 要设置的值类型
 * @param value 目标值（不同类型传对应格式：字符串传char*，数字传double*，布尔传int*）
 * @return 0成功，-1失败
 */
int cJSON_SetValue(cJSON *node, cJSON_ValueType type, const void *value) {
    // 基础校验
    if (node == NULL || value == NULL) {
        return -1;
    }

    // 根据类型修改对应字段
    switch (type) {
        case VAL_STRING: {
            // 释放原有字符串，避免内存泄漏
            if (node->valuestring != NULL) {
                free(node->valuestring);
            }
            node->valuestring = strdup((const char*)value);
            node->type = cJSON_String;
            break;
        }
        case VAL_NUMBER: {
            node->valuedouble = *(const double*)value;
            node->valueint = (int)*(const double*)value; // 兼容int字段
            node->type = cJSON_Number;
            break;
        }
        case VAL_BOOL: {
            int bool_val = *(const int*)value;
            node->type = bool_val ? cJSON_True : cJSON_False;
            break;
        }
        case VAL_NULL: {
            node->type = cJSON_NULL;
            break;
        }
        default:
            return -1;
    }
    return 0;
}

// 测试示例
int main() {
    // 构建原始JSON
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "name", "张三");
    cJSON_AddNumberToObject(root, "age", 25);
    cJSON_AddBoolToObject(root, "is_student", 1);

    printf("修改前：\n%s\n", cJSON_PrintPretty(root));

    // 快速修改值（核心调用）
    double new_age = 26;
    cJSON_SetValue(cJSON_GetObjectItem(root, "age"), VAL_NUMBER, &new_age);

    const char *new_name = "李四";
    cJSON_SetValue(cJSON_GetObjectItem(root, "name"), VAL_STRING, new_name);

    int new_bool = 0;
    cJSON_SetValue(cJSON_GetObjectItem(root, "is_student"), VAL_BOOL, &new_bool);

    printf("\n修改后：\n%s\n", cJSON_PrintPretty(root));

    // 释放资源
    cJSON_Delete(root);
    return 0;
}